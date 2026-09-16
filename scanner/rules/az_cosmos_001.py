"""AZ-COSMOS-001: required Cosmos DB local authentication remains enabled."""

import logging
from typing import Any, Dict, List

from scanner.rules._storage_common import policy_required

logger = logging.getLogger(__name__)

RULE_ID = "AZ-COSMOS-001"
RULE_NAME = "Cosmos DB Local Authentication Enabled"
SEVERITY = "HIGH"
CATEGORY = "Database"
FRAMEWORKS = {"CIS": "N/A-COSMOS-001", "NIST": "PR.AC-6", "ISO27001": "A.9.4.2", "SOC2": "CC6.3"}
DESCRIPTION = "An explicitly protected Cosmos DB account permits local key authentication."
REMEDIATION = "Disable local authentication after confirming all clients use Microsoft Entra authentication."
PLAYBOOK = "playbooks/cli/fix_az_cosmos_001.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    getter = getattr(azure_client, "get_cosmos_accounts", None)
    if getter is None:
        return findings
    accounts = getter()
    if accounts is None:
        logger.warning("%s: Cosmos DB inventory unavailable; result is indeterminate", RULE_ID)
        return findings
    for account in accounts:
        if not policy_required(account, "oshield:cosmos-local-auth-disabled"):
            continue
        value = getattr(account, "disable_local_auth", None)
        if value is None or value:
            continue
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": account.id,
                "resource_name": account.name,
                "resource_type": "Microsoft.DocumentDB/databaseAccounts",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {"disable_local_auth": value},
            }
        )
    return findings
