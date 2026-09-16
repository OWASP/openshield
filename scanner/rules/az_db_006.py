"""AZ-DB-006: required SQL vulnerability assessment is not enabled."""

from typing import Any, Dict, List

from scanner.rules._storage_common import policy_required

RULE_ID = "AZ-DB-006"
RULE_NAME = "SQL Vulnerability Assessment Not Configured"
SEVERITY = "HIGH"
CATEGORY = "Database"
FRAMEWORKS = {"CIS": "N/A-DB-006", "NIST": "DE.CM-8", "ISO27001": "A.12.6.1", "SOC2": "CC7.1"}
DESCRIPTION = "An explicitly protected Azure SQL server has no enabled vulnerability-assessment configuration."
REMEDIATION = "Enable SQL vulnerability assessment and configure an approved storage destination."
PLAYBOOK = "playbooks/cli/fix_az_db_006.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    get_assessment = getattr(azure_client, "get_sql_server_vulnerability_assessment", None)
    if get_assessment is None:
        return findings
    for server in azure_client.get_sql_servers():
        if not policy_required(server, "oshield:sql-va-required"):
            continue
        parsed = azure_client.parse_resource_id(getattr(server, "id", ""))
        if not parsed.get("resource_group"):
            continue
        policy = get_assessment(parsed["resource_group"], server.name)
        if policy is None:
            continue
        enabled = False if policy is False else getattr(policy, "is_enabled", True)
        if enabled:
            continue
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
                "metadata": {"vulnerability_assessment_enabled": enabled},
            }
        )
    return findings
