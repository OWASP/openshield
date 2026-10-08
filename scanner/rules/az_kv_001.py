"""AZ-KV-001: Key Vault with soft delete disabled."""

from typing import Any, Dict, List

RULE_ID = "AZ-KV-001"
RULE_NAME = "Key Vault with Soft Delete Disabled"
SEVERITY = "MEDIUM"
CATEGORY = "KeyVault"
FRAMEWORKS = {"CIS": "N/A-KV-001", "NIST": "PR.IP-4", "ISO27001": "A.8.14"}
DESCRIPTION = (
    "Azure Key Vault soft delete is disabled. Without soft delete, secrets, keys, "
    "and certificates can be permanently destroyed immediately upon deletion — "
    "whether by accident, a disgruntled insider, or an attacker who has gained access. "
    "Soft delete provides a recoverable state for 7–90 days after deletion."
)
REMEDIATION = (
    "Enable soft delete on the Key Vault. Note: once enabled, soft delete cannot be disabled. "
    "Also consider enabling purge protection to prevent permanent deletion during the retention period."
)
PLAYBOOK = "playbooks/cli/fix_az_kv_001.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect Key Vaults where enable_soft_delete is False or None."""
    findings: List[Dict[str, Any]] = []

    for vault in azure_client.get_key_vaults():
        props = getattr(vault, "properties", None)
        if props is None:
            continue

        # Soft delete defaults to True in Azure API version 2021-04-01+
        # but older vaults or explicitly disabled vaults may have it False.
        soft_delete = getattr(props, "enable_soft_delete", True)
        if soft_delete is False:
            parsed = azure_client.parse_resource_id(vault.id)
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": vault.id,
                    "resource_name": vault.name,
                    "resource_type": "Microsoft.KeyVault/vaults",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": parsed.get("resource_group", ""),
                        "location": getattr(vault, "location", ""),
                        "purge_protection": getattr(props, "enable_purge_protection", False),
                    },
                }
            )

    return findings
