"""AZ-STOR-008: required customer-managed key protection is absent."""

import logging
from typing import Any, Dict, List

from scanner.rules._storage_common import policy_required

logger = logging.getLogger(__name__)

RULE_ID = "AZ-STOR-008"
RULE_NAME = "Required Storage Customer-Managed Key Protection Missing"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {"CIS": "N/A-STOR-008", "NIST": "N/A-STOR-008", "ISO27001": "N/A-STOR-008", "SOC2": "N/A-STOR-008"}
DESCRIPTION = "This explicitly protected storage account is not using a customer-managed encryption key."
REMEDIATION = (
    "Configure storage encryption with an approved Key Vault customer-managed key "
    "after validating key access and rotation ownership."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_008.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for account in azure_client.get_storage_accounts():
        if not policy_required(account, "oshield:cmk-required"):
            continue
        encryption = getattr(account, "encryption", None)
        key_source = getattr(encryption, "key_source", None) if encryption else None
        if key_source is None:
            logger.warning("%s: encryption source unavailable; skipping", RULE_ID)
            continue
        source = str(key_source).strip().lower()
        if source in {"microsoft.keyvault", "keyvault", "microsoft.keyvaultmanaged"}:
            continue
        if source != "microsoft.storage":
            logger.warning("%s: unknown encryption source %r; skipping", RULE_ID, key_source)
            continue
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": account.id,
                "resource_name": account.name,
                "resource_type": "Microsoft.Storage/storageAccounts",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {"key_source": str(key_source), "requirement_tag": "oshield:cmk-required"},
            }
        )
    return findings
