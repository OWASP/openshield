"""AZ-DB-001: PostgreSQL server allows public network access."""

from typing import Any, Dict, List

RULE_ID = "AZ-DB-001"
RULE_NAME = "PostgreSQL Server Allows Public Network Access"
SEVERITY = "HIGH"
CATEGORY = "Database"
FRAMEWORKS = {"CIS": "4.3.1", "NIST": "PR.AC-3", "ISO27001": "A.8.20"}
DESCRIPTION = (
    "The Azure Database for PostgreSQL server is configured to allow public network access. "
    "This means the server endpoint is reachable from the public internet, increasing the "
    "attack surface. Database servers should only be accessible from trusted private networks."
)
REMEDIATION = (
    "Disable public network access on the PostgreSQL server and configure a private endpoint "
    "or VNet service endpoint to restrict connectivity to trusted networks only."
)
PLAYBOOK = "playbooks/cli/fix_az_db_001.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect PostgreSQL servers with public_network_access set to Enabled."""
    findings: List[Dict[str, Any]] = []

    for server in azure_client.get_postgresql_servers():
        public_access = getattr(server, "public_network_access", "Enabled")
        if str(public_access).lower() in ("enabled", "true", "1"):
            parsed = azure_client.parse_resource_id(server.id)
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": server.id,
                    "resource_name": server.name,
                    "resource_type": "Microsoft.DBforPostgreSQL/servers",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": parsed.get("resource_group", ""),
                        "location": getattr(server, "location", ""),
                    },
                }
            )

    return findings
