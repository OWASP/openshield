"""AZ-DB-003: PostgreSQL Flexible Server SSL enforcement disabled."""

from typing import Any, Dict, List
import logging

logger = logging.getLogger(__name__)

RULE_ID = "AZ-DB-003"
RULE_NAME = "PostgreSQL Flexible Server SSL Enforcement Disabled"
SEVERITY = "HIGH"
CATEGORY = "Database"
FRAMEWORKS = {"CIS": "4.3.6", "NIST": "PR.DS-2", "ISO27001": "A.8.24", "SOC2": "CC6.1"}
DESCRIPTION = (
    "The Azure Database for PostgreSQL Flexible Server has SSL enforcement disabled. "
    "Without SSL, data in transit between the application and database is transmitted "
    "in plaintext and is vulnerable to interception and man-in-the-middle attacks."
)
REMEDIATION = (
    "Enable SSL enforcement on the PostgreSQL Flexible Server by setting "
    "require_secure_transport to ON. "
    "Run: az postgres flexible-server parameter set --resource-group <rg> "
    "--server-name <server> --name require_secure_transport --value ON"
)
PLAYBOOK = "playbooks/cli/fix_az_db_003.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect PostgreSQL Flexible Servers with SSL enforcement disabled."""
    findings: List[Dict[str, Any]] = []

    for server in azure_client.get_postgresql_flexible_servers():
        parsed = azure_client.parse_resource_id(server.id)
        resource_group = parsed.get("resource_group", "")

        params = azure_client.get_postgresql_flexible_server_parameters(resource_group, server.name)

        if not params:
            # Cannot determine SSL state — skip to avoid false positives
            logger.warning(
                "az_db_003: skipping %s — get_postgresql_flexible_server_parameters "
                "returned empty (permission or API failure)",
                server.name,
            )
            continue

        ssl_param = next(
            (p for p in params if getattr(p, "name", "") == "require_secure_transport"),
            None,
        )

        if ssl_param is None:
            # Parameter not found — cannot determine compliance, skip
            logger.warning(
                "az_db_003: skipping %s — require_secure_transport parameter not found",
                server.name,
            )
            continue

        ssl_value = str(getattr(ssl_param, "value", "on")).lower()
        if ssl_value in ("off", "false", "0"):
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": server.id,
                    "resource_name": server.name,
                    "resource_type": "Microsoft.DBforPostgreSQL/flexibleServers",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": resource_group,
                        "location": getattr(server, "location", ""),
                        "ssl_value": ssl_value,
                    },
                }
            )

    return findings
