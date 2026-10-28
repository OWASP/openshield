"""Smoke tests for the OpenShield MCP server module."""

import json
import os
from unittest.mock import MagicMock, patch

from mcp.server import TOOLS, _subscription_is_authorized


def test_tools_count():
    """mcp/server.py must expose exactly 6 CSPM tool definitions."""
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


def test_call_tool_scan_subscription_blocked_when_not_authorized(monkeypatch):
    """scan_subscription returns an error when subscription_id is not on the allowlist."""
    monkeypatch.setenv("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS", "sub-allowed")
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake")
    monkeypatch.setenv("OPENSHIELD_TENANT_ID", "tenant-1")

    mock_pool = MagicMock()
    mock_conn = MagicMock()
    mock_pool.getconn.return_value = mock_conn

    captured = {"text": None}

    def fake_text_content(type, text):
        captured["text"] = text
        return MagicMock(text=text)

    fake_text_content_cls = MagicMock(side_effect=fake_text_content)

    captured_call_tool = {}

    def fake_call_tool_decorator():
        def decorator(fn):
            captured_call_tool["fn"] = fn
            return fn
        return decorator

    mock_server_instance = MagicMock()
    mock_server_instance.call_tool = fake_call_tool_decorator
    mock_server_instance.list_tools = MagicMock(return_value=lambda fn: fn)
    mock_server_cls = MagicMock(return_value=mock_server_instance)

    with patch("psycopg2.pool.SimpleConnectionPool", return_value=mock_pool), \
         patch("mcp.server._import_mcp", return_value=(mock_server_cls, MagicMock(), MagicMock(), fake_text_content_cls)):

        from mcp.server import _build_app
        _build_app()

        import asyncio
        asyncio.get_event_loop().run_until_complete(
            captured_call_tool["fn"]("scan_subscription", {"subscription_id": "sub-blocked"})
        )

    result_data = json.loads(captured["text"])
    assert "error" in result_data


def test_call_tool_tenant_id_comes_from_env(monkeypatch):
    """tenant_id is always sourced from OPENSHIELD_TENANT_ID, never from arguments."""
    monkeypatch.setenv("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS", "")
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake")
    monkeypatch.setenv("OPENSHIELD_TENANT_ID", "expected-tenant")

    mock_pool = MagicMock()
    mock_conn = MagicMock()
    mock_pool.getconn.return_value = mock_conn

    captured_tenant = {}

    def fake_get_findings(conn, subscription_id, tenant_id, **kwargs):
        captured_tenant["value"] = tenant_id
        return []

    captured_call_tool = {}

    def fake_call_tool_decorator():
        def decorator(fn):
            captured_call_tool["fn"] = fn
            return fn
        return decorator

    mock_server_instance = MagicMock()
    mock_server_instance.call_tool = fake_call_tool_decorator
    mock_server_instance.list_tools = MagicMock(return_value=lambda fn: fn)
    mock_server_cls = MagicMock(return_value=mock_server_instance)

    fake_text_content_cls = MagicMock(side_effect=lambda type, text: MagicMock(text=text))

    with patch("psycopg2.pool.SimpleConnectionPool", return_value=mock_pool), \
         patch("mcp.server._import_mcp", return_value=(mock_server_cls, MagicMock(), MagicMock(), fake_text_content_cls)), \
         patch("api.agent.tools.get_findings", fake_get_findings):

        from mcp.server import _build_app
        _build_app()

        import asyncio
        asyncio.get_event_loop().run_until_complete(
            captured_call_tool["fn"]("get_findings", {"subscription_id": "sub-x"})
        )

    assert captured_tenant.get("value") == "expected-tenant"
