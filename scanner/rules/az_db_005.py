"""AZ-DB-005: required Microsoft Entra-only authentication is disabled."""

from typing import Any, Dict, List

from scanner.rules._storage_common import policy_required

RULE_ID = "AZ-DB-005"
RULE_NAME = "SQL Server Microsoft Entra-Only Authentication Not Enforced"
SEVERITY = "HIGH"
CATEGORY = "Database"
FRAMEWORKS = {"CIS": "N/A-DB-005", "NIST": "PR.AC-6", "ISO27001": "A.9.4.2", "SOC2": "CC6.3"}
DESCRIPTION = (
    "An explicitly protected Azure SQL server permits SQL authentication instead of "
    "enforcing Microsoft Entra-only authentication."
)
REMEDIATION = "Enable Microsoft Entra-only authentication after confirming all clients use Entra identities."
PLAYBOOK = "playbooks/cli/fix_az_db_005.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    get_authentication = getattr(azure_client, "get_sql_server_azure_ad_only_authentication", None)
    if get_authentication is None:
        return findings
    for server in azure_client.get_sql_servers():
        if not policy_required(server, "oshield:entra-only-required"):
            continue
        parsed = azure_client.parse_resource_id(getattr(server, "id", ""))
        if not parsed.get("resource_group"):
            continue
        value = get_authentication(parsed["resource_group"], server.name)
        if value is None:
            continue
        if value:
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
                "metadata": {"azure_ad_only_authentication": value},
            }
        )
    return findings
