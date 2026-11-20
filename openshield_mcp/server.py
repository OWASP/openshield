"""OpenShield MCP server: exposes 6 CSPM tools to Claude Desktop and Copilot.

Run as a standalone script:
    python -m openshield_mcp.server

The server communicates over stdio using the Model Context Protocol.

This server is single-tenant and local: the tenant is fixed by the
OPENSHIELD_TENANT_ID environment variable and the LLM caller can never
override it. Write tools are additionally gated by OPENSHIELD_MCP_ROLE.

Required environment variables:
    DATABASE_URL          -- PostgreSQL connection string
    OPENSHIELD_TENANT_ID  -- Tenant identifier (never supplied by the LLM caller)

Optional environment variables:
    OPENSHIELD_MCP_ROLE                 -- viewer (default) | operator | admin.
                                           Write tools need operator/admin.
    OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS -- comma-separated subscription allowlist.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os

from api.agent.guardrails import can_call

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool definitions (plain dicts — loaded at import time, no mcp dependency).
# ---------------------------------------------------------------------------

_TOOL_SPECS: list[dict] = [
    {
        "name": "scan_subscription",
        "description": "Trigger an Azure subscription scan and return the scan_id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "subscription_id": {
                    "type": "string",
                    "description": "Azure subscription UUID",
                },
            },
            "required": ["subscription_id"],
        },
    },
    {
        "name": "get_findings",
        "description": ("Return security findings for a subscription, optionally filtered by severity or state."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "subscription_id": {"type": "string"},
                "severity": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    "description": "Optional severity filter",
                },
                "state": {
                    "type": "string",
                    "enum": ["OPEN", "RESOLVED", "REOPENED"],
                    "description": "Optional state filter",
                },
            },
            "required": ["subscription_id"],
        },
    },
    {
        "name": "get_compliance_posture",
        "description": ("Return compliance score and gaps for a framework (mcsb, cis, iso27001)."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "enum": ["mcsb", "cis", "iso27001"],
                },
                "subscription_id": {"type": "string"},
            },
            "required": ["framework", "subscription_id"],
        },
    },
    {
        "name": "get_attack_paths",
        "description": "Return BFS attack paths for a completed scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {
                    "type": "string",
                    "description": "UUID of the completed scan",
                },
            },
            "required": ["scan_id"],
        },
    },
    {
        "name": "explain_finding",
        "description": "Return full detail and risk context for a finding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "integer"},
            },
            "required": ["finding_id"],
        },
    },
    {
        "name": "suggest_remediation",
        "description": "Return step-by-step remediation guidance for a finding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "integer"},
            },
            "required": ["finding_id"],
        },
    },
]


def _import_mcp():
    """Import the installed mcp SDK, raising a clear error if it is missing.

    The package was renamed from ``mcp`` to ``openshield_mcp`` precisely so it
    no longer shadows the installed ``mcp`` SDK, so a plain import is safe. The
    import is deferred to runtime so this module can be imported in tests
    without the SDK present.
    """
    try:
        from mcp.server import Server as _Server
        from mcp.server.stdio import stdio_server as _stdio_server
        from mcp.types import TextContent as _TextContent, Tool as _Tool

        return _Server, _stdio_server, _Tool, _TextContent
    except ImportError as exc:
        raise ImportError(
            "The 'mcp' package is required to run the MCP server. Install it with: pip install mcp"
        ) from exc


def _make_tools(Tool):
    """Convert _TOOL_SPECS to mcp.types.Tool objects."""
    return [Tool(**spec) for spec in _TOOL_SPECS]


# TOOLS is a list of plain dicts at import time so the module can be imported
# in tests without needing the mcp runtime to be fully loadable.
TOOLS = _TOOL_SPECS


# ---------------------------------------------------------------------------
# MCP server (built only when the module is run as __main__)
# ---------------------------------------------------------------------------


def _subscription_is_authorized(subscription_id: str) -> bool:
    """Allowlist check mirroring api/routes/scans.py.

    Reads OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS (comma-separated). When unset,
    every subscription is accepted. This prevents prompt-injected calls from
    scanning arbitrary subscriptions via the MCP server.
    """
    raw = os.environ.get("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS", "")
    allowlist = {v.strip().lower() for v in raw.split(",") if v.strip()}
    return not allowlist or subscription_id.lower() in allowlist


def _role_allows(tool_name: str) -> bool:
    """Whether the configured MCP role may call a tool.

    Role comes from OPENSHIELD_MCP_ROLE (default "viewer"). Write tools require
    operator/admin, enforced through the same guardrail the HTTP API uses.
    """
    return can_call(tool_name, os.environ.get("OPENSHIELD_MCP_ROLE", "viewer"))


def _build_app():
    """Construct and return a fully wired MCP Server instance."""
    from api.models.finding import DatabaseManager

    Server, stdio_server, Tool, TextContent = _import_mcp()
    tools = _make_tools(Tool)
    app = Server("openshield-cspm")

    from api.agent.tools import (
        explain_finding,
        get_attack_paths,
        get_compliance_posture,
        get_findings,
        scan_subscription,
        suggest_remediation,
    )

    db_url = os.environ["DATABASE_URL"]
    # tenant_id always comes from env — never from LLM tool-call arguments.
    tenant_id = os.environ["OPENSHIELD_TENANT_ID"]
    db = DatabaseManager(db_url)
    db.connect()

    @app.list_tools()
    async def list_tools() -> list:
        return tools

    @app.call_tool()
    async def call_tool(name: str, arguments: dict):
        # Write tools are gated by the configured MCP role before anything else.
        if not _role_allows(name):
            return [TextContent(type="text", text=json.dumps({"error": "insufficient_permissions"}))]
        try:
            if name == "scan_subscription":
                sub_id = arguments["subscription_id"]
                if not _subscription_is_authorized(sub_id):
                    result = {"error": "subscription_id is not authorized for this deployment"}
                else:
                    # scan_subscription takes the manager (shared admission path).
                    result = scan_subscription(db, sub_id, tenant_id)
            elif name == "get_findings":
                sub_id = arguments["subscription_id"]
                if not _subscription_is_authorized(sub_id):
                    result = {"error": "subscription_id is not authorized for this deployment"}
                else:
                    result = get_findings(
                        db.conn,
                        sub_id,
                        tenant_id,
                        severity=arguments.get("severity"),
                        state=arguments.get("state"),
                    )
            elif name == "get_compliance_posture":
                sub_id = arguments["subscription_id"]
                if not _subscription_is_authorized(sub_id):
                    result = {"error": "subscription_id is not authorized for this deployment"}
                else:
                    result = get_compliance_posture(
                        db.conn,
                        arguments["framework"],
                        sub_id,
                        tenant_id,
                    )
            elif name == "get_attack_paths":
                result = get_attack_paths(db.conn, arguments["scan_id"], tenant_id)
            elif name == "explain_finding":
                result = explain_finding(db.conn, arguments["finding_id"], tenant_id)
            elif name == "suggest_remediation":
                result = suggest_remediation(db.conn, arguments["finding_id"], tenant_id)
            else:
                result = {"error": f"unknown tool: {name}"}
        except Exception as exc:
            logger.exception("Tool %s failed", name)
            result = {"error": str(exc)}
        return [TextContent(type="text", text=json.dumps(result))]

    return app, stdio_server


async def _main():
    app, stdio_server = _build_app()
    async with stdio_server() as streams:
        await app.run(*streams, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
