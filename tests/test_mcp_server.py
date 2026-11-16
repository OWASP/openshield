"""Smoke and RBAC tests for the OpenShield MCP server module."""

import asyncio
import json
from unittest.mock import MagicMock, patch

from openshield_mcp.server import TOOLS, _role_allows, _subscription_is_authorized


def test_tools_count():
    """openshield_mcp/server.py must expose exactly 6 CSPM tool definitions."""
    assert len(TOOLS) == 6


def test_tool_names():
    """Each tool spec must have a unique non-empty name."""
    names = [t["name"] for t in TOOLS]
    assert sorted(names) == sorted(
        [
            "scan_subscription",
            "get_findings",
            "get_compliance_posture",
            "get_attack_paths",
            "explain_finding",
            "suggest_remediation",
        ]
    )


def test_tool_schemas():
    """Every tool must have an inputSchema with at least one required field."""
    for tool in TOOLS:
        schema = tool["inputSchema"]
        assert schema.get("type") == "object"
        assert "properties" in schema
        assert "required" in schema
        assert len(schema["required"]) >= 1


def test_subscription_is_authorized_no_allowlist(monkeypatch):
    """Without an allowlist configured, any subscription_id is accepted."""
    monkeypatch.delenv("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS", raising=False)
    assert _subscription_is_authorized("any-sub-id") is True


def test_subscription_is_authorized_with_allowlist(monkeypatch):
    """When an allowlist is set, only listed subscriptions pass."""
    monkeypatch.setenv("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS", "sub-aaa,sub-bbb")
    assert _subscription_is_authorized("sub-aaa") is True
    assert _subscription_is_authorized("SUB-BBB") is True  # case-insensitive
    assert _subscription_is_authorized("sub-ccc") is False


def test_role_allows_gates_write_tools(monkeypatch):
    """Write tools need operator/admin; read tools are always allowed."""
    monkeypatch.setenv("OPENSHIELD_MCP_ROLE", "viewer")
    assert _role_allows("scan_subscription") is False
    assert _role_allows("get_findings") is True

    monkeypatch.setenv("OPENSHIELD_MCP_ROLE", "operator")
    assert _role_allows("scan_subscription") is True

    monkeypatch.setenv("OPENSHIELD_MCP_ROLE", "admin")
    assert _role_allows("scan_subscription") is True

    # Unset role defaults to viewer (fail closed for writes).
    monkeypatch.delenv("OPENSHIELD_MCP_ROLE", raising=False)
    assert _role_allows("scan_subscription") is False


# ---------------------------------------------------------------------------
# call_tool wiring
# ---------------------------------------------------------------------------


def _build_call_tool(monkeypatch, fake_db=None, tool_overrides=None):
    """Build the app with mocked mcp SDK + DatabaseManager, returning call_tool.

    ``tool_overrides`` maps api.agent.tools names to fakes; these must be
    patched while _build_app runs because the server imports the tool functions
    by name at build time.
    """
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake")
    monkeypatch.setenv("OPENSHIELD_TENANT_ID", "expected-tenant")

    captured = {}

    def fake_call_tool_decorator():
        def decorator(fn):
            captured["fn"] = fn
            return fn

        return decorator

    server_instance = MagicMock()
    server_instance.call_tool = fake_call_tool_decorator
    server_instance.list_tools = MagicMock(return_value=lambda fn: fn)
    server_cls = MagicMock(return_value=server_instance)

    text_content_cls = MagicMock(side_effect=lambda type, text: MagicMock(text=text))
    mcp_mocks = (server_cls, MagicMock(), MagicMock(), text_content_cls)

    db_instance = fake_db if fake_db is not None else MagicMock()
    db_cls = MagicMock(return_value=db_instance)

    with patch("openshield_mcp.server._import_mcp", return_value=mcp_mocks), patch(
        "api.models.finding.DatabaseManager", db_cls
    ):
        for name, fn in (tool_overrides or {}).items():
            monkeypatch.setattr(f"api.agent.tools.{name}", fn)
        from openshield_mcp.server import _build_app

        _build_app()

    return captured["fn"], db_instance


def _run(fn, name, arguments):
    return asyncio.new_event_loop().run_until_complete(fn(name, arguments))


def test_call_tool_scan_denied_for_viewer_role(monkeypatch):
    """A viewer role is denied scan_subscription before any work happens."""
    monkeypatch.setenv("OPENSHIELD_MCP_ROLE", "viewer")
    monkeypatch.setenv("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS", "")

    fake_db = MagicMock()
    fn, _ = _build_call_tool(monkeypatch, fake_db=fake_db)
    result = _run(fn, "scan_subscription", {"subscription_id": "sub-x"})

    data = json.loads(result[0].text)
    assert data == {"error": "insufficient_permissions"}
    fake_db.admit_scan.assert_not_called()


def test_call_tool_scan_blocked_when_not_authorized(monkeypatch):
    """With a privileged role, an un-allowlisted subscription is still rejected."""
    monkeypatch.setenv("OPENSHIELD_MCP_ROLE", "operator")
    monkeypatch.setenv("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS", "sub-allowed")

    fake_db = MagicMock()
    fn, _ = _build_call_tool(monkeypatch, fake_db=fake_db)
    result = _run(fn, "scan_subscription", {"subscription_id": "sub-blocked"})

    data = json.loads(result[0].text)
    assert "error" in data
    assert "not authorized" in data["error"]
    fake_db.admit_scan.assert_not_called()


def test_call_tool_tenant_id_comes_from_env(monkeypatch):
    """tenant_id is always sourced from OPENSHIELD_TENANT_ID, never from arguments."""
    monkeypatch.setenv("OPENSHIELD_MCP_ROLE", "viewer")
    monkeypatch.setenv("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS", "")

    captured_tenant = {}

    def fake_get_findings(conn, subscription_id, tenant_id, **kwargs):
        captured_tenant["value"] = tenant_id
        return []

    fn, _ = _build_call_tool(monkeypatch, tool_overrides={"get_findings": fake_get_findings})
    _run(fn, "get_findings", {"subscription_id": "sub-x"})

    assert captured_tenant.get("value") == "expected-tenant"
