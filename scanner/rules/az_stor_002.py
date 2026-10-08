"""AZ-STOR-002: Storage account not configured for HTTPS-only traffic."""

from typing import Any, Dict, List

RULE_ID = "AZ-STOR-002"
RULE_NAME = "Storage Account Allows HTTP Traffic (Not HTTPS-Only)"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {"CIS": "3.1", "NIST": "PR.DS-2", "ISO27001": "A.8.24"}
DESCRIPTION = (
    "Storage accounts that do not enforce HTTPS-only traffic allow data to be "
    "transmitted in plaintext over HTTP. This exposes credentials and data to "
    "man-in-the-middle attacks and interception."
)
REMEDIATION = (
    "Enable the 'Secure transfer required' setting on the storage account. "
    "Navigate to Storage Account > Configuration > Secure transfer required and enable it."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_002.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect storage accounts where enable_https_traffic_only is False."""
    findings: List[Dict[str, Any]] = []

    for account in azure_client.get_storage_accounts():
        if not getattr(account, "enable_https_traffic_only", True):
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
                }
            )

    return findings
