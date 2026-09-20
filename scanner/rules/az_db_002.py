"""AZ-DB-002: Azure SQL server has no auditing configured."""

import logging
from typing import Any, Dict, List

from scanner.azure_client import enum_str

RULE_ID = "AZ-DB-002"
RULE_NAME = "Azure SQL Server Has No Auditing Configured"
SEVERITY = "MEDIUM"
CATEGORY = "Database"
FRAMEWORKS = {"CIS": "4.1.3", "NIST": "DE.CM-7", "ISO27001": "A.12.4.1"}
DESCRIPTION = (
    "Azure SQL Server auditing is disabled. Without auditing, database access, "
    "schema changes, and failed login attempts are not logged, making forensic "
    "investigation and compliance reporting impossible."
)
REMEDIATION = (
    "Enable SQL Server auditing and configure a storage account, Log Analytics "
    "workspace, or Event Hub as the audit log destination. "
    "Retain logs for at least 90 days to satisfy most compliance frameworks."
)
PLAYBOOK = "playbooks/cli/fix_az_db_002.sh"

# A failed auditing-policy lookup is reported as an unknown scan result, not
# a confirmed violation: it says nothing about whether auditing is actually
# enabled, so it must not carry the standard MEDIUM severity or remediation
# (which could send someone to re-configure auditing that was already
# compliant). This mirrors the indeterminate-finding convention used by
# AZ-CMP-002 for unreadable disks.
INDETERMINATE_SEVERITY = "LOW"
INDETERMINATE_DESCRIPTION = (
    "The auditing policy for this Azure SQL Server could not be retrieved, so its "
    "auditing configuration could not be verified. This is not a confirmed "
    "violation — the scanning principal could not resolve the server's auditing "
    "policy (missing permissions, transient API failure, or throttling)."
)
INDETERMINATE_REMEDIATION = (
    "Grant the scanning principal permission to read the SQL Server's auditing "
    "policy (Microsoft.Sql/servers/auditingSettings/read) and re-run the scan "
    "to determine the actual auditing state."
)

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect SQL servers where server-level blob auditing is disabled."""
    findings: List[Dict[str, Any]] = []

    for server in azure_client.get_sql_servers():
        parsed = azure_client.parse_resource_id(server.id)
        resource_group = parsed.get("resource_group", "")
        if not resource_group:
            logger.warning(
                "Skipping AZ-DB-002 check for %s: could not parse resource group from malformed ARM ID %r",
                getattr(server, "name", "<unknown>"),
                getattr(server, "id", ""),
            )
            continue

        policy = azure_client.get_sql_server_auditing_policy(resource_group, server.name)
        if policy is None:
            # Could not retrieve the policy (API/auth failure, throttling, etc).
            # We don't know the actual auditing state, so this is reported as
            # an indeterminate LOW finding rather than a confirmed violation
            # or a silent skip — the gap stays visible in scan output.
            logger.warning(
                "AZ-DB-002: could not retrieve auditing policy for %s, marking indeterminate",
                server.name,
            )
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": INDETERMINATE_SEVERITY,
                    "category": CATEGORY,
                    "resource_id": server.id,
                    "resource_name": server.name,
                    "resource_type": "Microsoft.Sql/servers",
                    "description": INDETERMINATE_DESCRIPTION,
                    "remediation": INDETERMINATE_REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": resource_group,
                        "determination": "indeterminate",
                    },
                }
            )
            continue

        state = enum_str(getattr(policy, "state", None), default="Disabled")
        is_disabled = state.lower() != "enabled"

        if is_disabled:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": server.id,
                    "resource_name": server.name,
                    "resource_type": "Microsoft.Sql/servers",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": resource_group,
                        "auditing_state": state,
                        "determination": "non_compliant",
                    },
                }
            )

    return findings
