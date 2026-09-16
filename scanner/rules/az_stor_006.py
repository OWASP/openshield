"""AZ-STOR-006: Storage account shared-key authorization remains enabled."""

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

RULE_ID = "AZ-STOR-006"
RULE_NAME = "Storage Account Shared-Key Authorization Enabled"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {
    "CIS": "N/A-STOR-006",
    "NIST": "N/A-STOR-006",
    "ISO27001": "N/A-STOR-006",
    "SOC2": "N/A-STOR-006",
}
DESCRIPTION = (
    "Shared-key authorization is enabled on this storage account. Shared keys "
    "are long-lived account-wide credentials and bypass identity-based access "
    "controls when disclosed."
)
REMEDIATION = (
    "Disable shared-key authorization after confirming that all clients use "
    "Microsoft Entra ID or an approved alternative. Navigate to Storage Account "
    "> Configuration > Allow storage account key access and set it to Disabled."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_006.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Flag accounts where shared-key access is enabled or unset.

    Azure documents allow_shared_key_access=None as equivalent to True:
    an account with no explicit setting permits Shared Key authorization.
    Only False (explicitly disabled) is compliant.
    """
    findings: List[Dict[str, Any]] = []
    for account in azure_client.get_storage_accounts():
        state = getattr(account, "allow_shared_key_access", None)
        if state is False:
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
                "metadata": {"allow_shared_key_access": state},
            }
        )
    return findings
