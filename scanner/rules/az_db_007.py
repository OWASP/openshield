"""AZ-DB-007: required SQL audit retention is below policy."""

from typing import Any, Dict, List

from scanner.azure_client import enum_str
from scanner.rules._storage_common import policy_required

RULE_ID = "AZ-DB-007"
RULE_NAME = "SQL Auditing Retention Below Minimum"
SEVERITY = "MEDIUM"
CATEGORY = "Database"
FRAMEWORKS = {"CIS": "N/A-DB-007", "NIST": "PR.PT-1", "ISO27001": "A.12.4.1", "SOC2": "CC7.2"}
DESCRIPTION = "An explicitly protected Azure SQL server retains audit logs for less than the required 90 days."
REMEDIATION = "Enable SQL auditing and set retention to at least 90 days in an approved destination."
PLAYBOOK = "playbooks/cli/fix_az_db_007.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    get_audit = getattr(azure_client, "get_sql_server_auditing_policy", None)
    if get_audit is None:
        return findings
    for server in azure_client.get_sql_servers():
        if not policy_required(server, "oshield:sql-audit-required"):
            continue
        parsed = azure_client.parse_resource_id(getattr(server, "id", ""))
        if not parsed.get("resource_group"):
            continue
        policy = get_audit(parsed["resource_group"], server.name)
        if policy is None:
            continue
        state = "missing" if policy is False else enum_str(getattr(policy, "state", None)).lower()
        if state != "enabled":
            retention = 0
        else:
            retention = getattr(policy, "retention_days", None)
            if retention is None:
                retention = getattr(policy, "retention_period", None)
            if retention is None or not isinstance(retention, int):
                continue
            if retention == 0 or retention >= 90:
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
                "metadata": {"state": state, "retention_days": retention, "minimum_days": 90},
            }
        )
    return findings
