"""AZ-KV-004: Key Vault purge protection disabled."""

from typing import Any, Dict, List

RULE_ID = "AZ-KV-004"
RULE_NAME = "Key Vault Purge Protection Disabled"
SEVERITY = "MEDIUM"
CATEGORY = "KeyVault"
FRAMEWORKS = {"CIS": "8.5", "NIST": "PR.IP-4", "ISO27001": "A.8.14", "SOC2": "CC9.1"}
DESCRIPTION = (
    "Azure Key Vaults without purge protection enabled allow permanent "
    "deletion of vaults and their secrets, keys, and certificates during "
    "the soft-delete retention period. Without purge protection, a "
    "malicious insider or accidental deletion can result in irrecoverable "
    "loss of cryptographic material."
)
REMEDIATION = (
    "Enable purge protection on the Key Vault. Note: once enabled, "
    "purge protection cannot be disabled. Ensure soft delete is also "
    "enabled as purge protection requires it."
)
PLAYBOOK = "playbooks/cli/fix_az_kv_004.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return a list of findings. Return [] if no issues are found."""
    findings: List[Dict[str, Any]] = []

    for vault in azure_client.get_key_vaults():
        parsed = azure_client.parse_resource_id(vault.id)
        resource_group = parsed["resource_group"]
        vault_name = parsed["name"]

        properties = getattr(vault, "properties", None)
        purge_protection = getattr(properties, "enable_purge_protection", False)

        if not purge_protection:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": vault.id,
                    "resource_name": vault_name,
                    "resource_type": "Microsoft.KeyVault/vaults",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": resource_group,
                        "location": getattr(vault, "location", ""),
                    },
                }
            )

    return findings
