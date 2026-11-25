# OpenShield MCP Server

This server exposes the 6 OpenShield CSPM tools to any MCP-compatible host
(Claude Desktop, GitHub Copilot, or any other MCP client) over stdio.

## What it does

The server makes the following tools available to connected LLM hosts:

| Tool | Description |
|------|-------------|
| `scan_subscription` | Trigger an Azure subscription scan and return the scan_id |
| `get_findings` | Return security findings, optionally filtered by severity or state |
| `get_compliance_posture` | Return compliance score and gaps for cis, nist, iso27001, soc2, and other supported frameworks |
| `get_attack_paths` | Return BFS attack paths for a completed scan |
| `explain_finding` | Return full detail and risk context for a finding |
| `suggest_remediation` | Return step-by-step remediation guidance for a finding |

This server is single-tenant and local: it serves exactly the one tenant named
by `OPENSHIELD_TENANT_ID`, and the LLM caller never supplies or influences the
tenant identifier. It is not a multi-tenant boundary; run one instance per
tenant.

## Prerequisites

- Python 3.11+
- `pip install mcp psycopg2-binary`
- A running PostgreSQL database reachable via `DATABASE_URL`

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string, e.g. `postgresql://user:pass@host/db` |
| `OPENSHIELD_TENANT_ID` | Yes | Tenant identifier passed to tool functions for audit logging; subscription-level isolation is enforced via subscription_id from the allowlist |
| `OPENSHIELD_MCP_ROLE` | No | `viewer` (default), `operator`, or `admin`. Write tools (`scan_subscription`) require `operator`/`admin` |
| `OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS` | No | Comma-separated allowlist of subscription IDs that may be scanned |

## Adding to Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "openshield-cspm": {
      "command": "python",
      "args": ["-m", "openshield_mcp.server"],
      "cwd": "/path/to/openshield",
      "env": {
        "DATABASE_URL": "postgresql://user:pass@localhost/openshield",
        "OPENSHIELD_TENANT_ID": "your-tenant-id"
      }
    }
  }
}
```

Restart Claude Desktop after saving. The six CSPM tools will appear in the
tool picker.

## Running standalone

```bash
DATABASE_URL=postgresql://user:pass@localhost/openshield \
OPENSHIELD_TENANT_ID=my-tenant \
python -m openshield_mcp.server
```

The server speaks JSON-RPC over stdin/stdout and is designed to be launched
by an MCP host process, not run interactively.

## Security notes

- `OPENSHIELD_TENANT_ID` is always read from the environment. The LLM cannot
  override it through tool arguments.
- Write tools are gated by `OPENSHIELD_MCP_ROLE`: `scan_subscription` is denied
  unless the role is `operator` or `admin`, mirroring the HTTP API's RBAC.
- `scan_subscription` goes through the shared scan-admission path (advisory
  lock, idempotency, one-active-scan), so it cannot stampede scans.
- No Flask or HTTP server code is present in this module.
