"""OpenShield MCP server: exposes 6 CSPM tools to Claude Desktop and Copilot.

Run as a standalone script:
    python -m mcp.server

The server communicates over stdio using the Model Context Protocol.

Required environment variables:
    DATABASE_URL          — PostgreSQL connection string
    OPENSHIELD_TENANT_ID  — Tenant identifier (never supplied by the LLM caller)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool definitions (plain dicts — loaded at import time, no mcp dependency).
# The TOOLS list is intentionally a list of dicts here so that the module can
# be imported for testing without the installed mcp package.  The _make_tools()
# helper converts them to mcp.types.Tool objects at runtime.
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
    """Import the installed mcp package, raising a clear error if missing.

    The local mcp/ package shadows the installed one, so we temporarily
    remove the project root from sys.path before importing, then restore it.
    """
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    saved = sys.path[:]
    # Remove project root so installed mcp is found instead of this package
    sys.path = [p for p in sys.path if os.path.normcase(os.path.abspath(p)) != os.path.normcase(project_root)]
    # Remove any stale local mcp entries
    stale = [k for k in sys.modules if k == "mcp" or k.startswith("mcp.")]
    for k in stale:
        del sys.modules[k]
    try:
        from mcp.server import Server as _Server
        from mcp.server.stdio import stdio_server as _stdio_server
        from mcp.types import Tool as _Tool, TextContent as _TextContent

        return _Server, _stdio_server, _Tool, _TextContent
    except ImportError as exc:
        raise ImportError(
            "The 'mcp' package is required to run the MCP server. Install it with: pip install mcp"
        ) from exc
    finally:
        sys.path = saved


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


def _build_app():
    """Construct and return a fully wired MCP Server instance."""
    try:
        from psycopg2 import pool as _pg_pool
    except ImportError as exc:
        raise ImportError("psycopg2 is required: pip install psycopg2-binary") from exc

    from api.agent.tools import (
        explain_finding,
        get_attack_paths,
        get_compliance_posture,
        get_findings,
        scan_subscription,
        suggest_remediation,
    )

    Server, stdio_server, Tool, TextContent = _import_mcp()
    tools = _make_tools(Tool)
    app = Server("openshield-cspm")

    db_url = os.environ["DATABASE_URL"]
    # tenant_id always comes from env — never from LLM tool-call arguments
    tenant_id = os.environ["OPENSHIELD_TENANT_ID"]
    _pool = _pg_pool.SimpleConnectionPool(1, 5, db_url)

    @app.list_tools()
    async def list_tools() -> list:
        return tools

    @app.call_tool()
    async def call_tool(name: str, arguments: dict):
        conn = _pool.getconn()
        try:
            if name == "scan_subscription":
                sub_id = arguments["subscription_id"]
                if not _subscription_is_authorized(sub_id):
                    result = {"error": "subscription_id is not authorized for this deployment"}
                else:
                    result = scan_subscription(conn, sub_id, tenant_id)
            elif name == "get_findings":
                result = get_findings(
                    conn,
                    arguments["subscription_id"],
                    tenant_id,
                    severity=arguments.get("severity"),
                    state=arguments.get("state"),
                )
            elif name == "get_compliance_posture":
                result = get_compliance_posture(
                    conn,
                    arguments["framework"],
                    arguments["subscription_id"],
                    tenant_id,
                )
            elif name == "get_attack_paths":
                result = get_attack_paths(conn, arguments["scan_id"], tenant_id)
            elif name == "explain_finding":
                result = explain_finding(conn, arguments["finding_id"], tenant_id)
            elif name == "suggest_remediation":
                result = suggest_remediation(conn, arguments["finding_id"], tenant_id)
            else:
                result = {"error": f"unknown tool: {name}"}
        except Exception as exc:
            logger.exception("Tool %s failed", name)
            result = {"error": str(exc)}
        finally:
            _pool.putconn(conn)
        return [TextContent(type="text", text=json.dumps(result))]

    return app, stdio_server


async def _main():
    app, stdio_server = _build_app()
    async with stdio_server() as streams:
        await app.run(*streams, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
