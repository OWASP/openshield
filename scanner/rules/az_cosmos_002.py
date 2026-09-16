"""AZ-COSMOS-002: required Cosmos DB private access is not enforced."""

import logging
from typing import Any, Dict, List

from scanner.rules._storage_common import policy_required

logger = logging.getLogger(__name__)

RULE_ID = "AZ-COSMOS-002"
RULE_NAME = "Cosmos DB Public Network Access Enabled"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "N/A-COSMOS-002", "NIST": "PR.AC-5", "ISO27001": "A.13.1.1", "SOC2": "CC6.6"}
DESCRIPTION = "An explicitly protected Cosmos DB account allows public network access."
REMEDIATION = "Disable public network access and use approved private connectivity or an explicit exception."
PLAYBOOK = "playbooks/cli/fix_az_cosmos_002.sh"


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
        if not policy_required(account, "oshield:cosmos-public-access-disabled"):
            continue
        value = getattr(account, "public_network_access", None)
        if value is None or str(getattr(value, "value", value)).strip().lower() in {"disabled", "false", "none"}:
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
                "metadata": {"public_network_access": str(value)},
            }
        )
    return findings
