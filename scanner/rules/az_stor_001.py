"""AZ-STOR-001: Storage account with public blob access enabled."""

from typing import Any, Dict, List

RULE_ID = "AZ-STOR-001"
RULE_NAME = "Public Blob Access Enabled on Storage Account"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {"CIS": "3.5", "NIST": "PR.AC-3", "ISO27001": "A.8.3"}
DESCRIPTION = (
    "Storage accounts with public blob access enabled allow unauthenticated "
    "read access to blob data over the internet. This setting can expose "
    "sensitive files, backups, or configuration data to any external actor."
)
REMEDIATION = (
    "Disable public blob access on the storage account. "
    "Navigate to Storage Account > Configuration > Blob public access and set it to Disabled."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_001.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect storage accounts with allow_blob_public_access set to True."""
    findings: List[Dict[str, Any]] = []

    for account in azure_client.get_storage_accounts():
        if getattr(account, "allow_blob_public_access", False):
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
