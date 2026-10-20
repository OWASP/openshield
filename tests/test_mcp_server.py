"""Smoke tests for the OpenShield MCP server module."""

from mcp.server import TOOLS


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
