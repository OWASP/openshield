# OpenShield MCP Server

This server exposes the 6 OpenShield CSPM tools to any MCP-compatible host
(Claude Desktop, GitHub Copilot, or any other MCP client) over stdio.

## What it does

The server makes the following tools available to connected LLM hosts:

| Tool | Description |
|------|-------------|
| `scan_subscription` | Trigger an Azure subscription scan and return the scan_id |
| `get_findings` | Return security findings, optionally filtered by severity or state |
| `get_compliance_posture` | Return compliance score and gaps for mcsb, cis, or iso27001 |
| `get_attack_paths` | Return BFS attack paths for a completed scan |
| `explain_finding` | Return full detail and risk context for a finding |
| `suggest_remediation` | Return step-by-step remediation guidance for a finding |

Tenant isolation is enforced server-side via `OPENSHIELD_TENANT_ID`. The LLM
caller never supplies or influences the tenant identifier.

## Prerequisites

- Python 3.11+
- `pip install mcp psycopg2-binary`
- A running PostgreSQL database reachable via `DATABASE_URL`

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string, e.g. `postgresql://user:pass@host/db` |
| `OPENSHIELD_TENANT_ID` | Yes | Tenant identifier used for row-level isolation |

## Adding to Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "openshield-cspm": {
      "command": "python",
      "args": ["-m", "mcp.server"],
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
python -m mcp.server
```

The server speaks JSON-RPC over stdin/stdout and is designed to be launched
by an MCP host process, not run interactively.

## Security notes

- `OPENSHIELD_TENANT_ID` is always read from the environment. The LLM cannot
  override it through tool arguments.
- Each tool call opens and closes its own database connection (stateless per
  call). No connection is held between calls.
- No Flask or HTTP server code is present in this module.
