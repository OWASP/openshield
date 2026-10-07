"""AZ-KV-003: Key Vault without diagnostic logging enabled."""

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

RULE_ID = "AZ-KV-003"
RULE_NAME = "Key Vault Without Diagnostic Logging Enabled"
SEVERITY = "MEDIUM"
CATEGORY = "KeyVault"

FRAMEWORKS = {"CIS": "8.4", "NIST": "DE.CM-7", "ISO27001": "A.8.15", "SOC2": "CC7.2"}

DESCRIPTION = (
    "Azure Key Vault diagnostic logging is not enabled. Without diagnostic "
    "logs, access to secrets, keys, and certificates is not recorded, "
    "reducing visibility into unauthorized access attempts and preventing "
    "effective forensic investigation."
)

REMEDIATION = (
    "Enable diagnostic settings for the Key Vault and configure logs to be "
    "sent to Log Analytics, Event Hub, or a Storage Account."
)

PLAYBOOK = "playbooks/cli/fix_az_kv_003.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect Key Vaults with missing or disabled diagnostic logging."""
    findings: List[Dict[str, Any]] = []

    for vault in azure_client.get_key_vaults():
        status = azure_client.get_diagnostic_settings(vault.id)

        if status is None:
            logger.warning(
                "%s: could not determine diagnostic settings for %s",
                RULE_ID,
                vault.name,
            )
            continue

        if status is False:
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
                    },
                }
            )

    return findings
