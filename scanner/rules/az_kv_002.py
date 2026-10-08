"""AZ-KV-002: Key Vault allows public network access without private endpoint."""

from typing import Any, Dict, List

RULE_ID = "AZ-KV-002"
RULE_NAME = "Key Vault Allows Public Network Access Without Private Endpoint"
SEVERITY = "HIGH"
CATEGORY = "KeyVault"
FRAMEWORKS = {"CIS": "8.7", "NIST": "AC-17", "ISO27001": "A.8.20"}

DESCRIPTION = (
    "The Azure Key Vault is accessible over the public internet without a private endpoint configured. "
    "This increases the risk of unauthorized access to sensitive secrets, keys, and certificates."
)

REMEDIATION = (
    "Disable public network access for the Key Vault and configure a private endpoint "
    "to restrict access to trusted virtual networks."
)

PLAYBOOK = "playbooks/cli/fix_az_kv_002.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect Key Vaults with public network access enabled and no private endpoint configured."""
    findings: List[Dict[str, Any]] = []

    for vault in azure_client.get_key_vaults():
        props = getattr(vault, "properties", None)
        if not props:
            continue

        # Handle SDK inconsistencies (snake_case vs camelCase)
        public_access = getattr(props, "public_network_access", None)
        if public_access is None:
            public_access = getattr(props, "publicNetworkAccess", None)

        private_endpoints = getattr(props, "private_endpoint_connections", None)
        if private_endpoints is None:
            private_endpoints = getattr(props, "privateEndpointConnections", None)

        # Normalize values safely
        is_public = str(public_access).lower() in ("enabled", "true", "1")
        has_private_endpoint = bool(private_endpoints) and len(private_endpoints) > 0

        if is_public and not has_private_endpoint:
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
