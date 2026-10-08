"""AZ-KV-005: Key Vault certificate expiring within 30 days."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

RULE_ID = "AZ-KV-005"
RULE_NAME = "Key Vault Certificate Expiring Within 30 Days"
SEVERITY = "MEDIUM"
CATEGORY = "KeyVault"
FRAMEWORKS = {
    "CIS": "N/A-KV-005",
    "NIST": "PR.MA-1",
    "ISO27001": "A.8.24",
    "SOC2": "CC9.1",
}
DESCRIPTION = (
    "A certificate stored in Azure Key Vault is expiring within 30 days "
    "and does not have auto-renewal configured. Expired certificates cause "
    "immediate service outages, broken HTTPS connections, and failed "
    "authentication flows."
)
REMEDIATION = (
    "Enable auto-renewal on the certificate in Azure Key Vault, or manually "
    "renew the certificate before it expires. Navigate to: "
    "Key Vault > Certificates > select certificate > Issuance Policy > "
    "enable Auto-renewal."
)
PLAYBOOK = "playbooks/cli/fix_az_kv_005.sh"

logger = logging.getLogger(__name__)

EXPIRY_THRESHOLD_DAYS = 30


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for vault in azure_client.get_key_vaults():
        parsed = azure_client.parse_resource_id(getattr(vault, "id", ""))
        rg = parsed.get("resource_group", "")
        vault_name = parsed.get("name", "")
        if not rg or not vault_name:
            continue

        certificates = azure_client.get_key_vault_certificates(vault_name)
        for cert in certificates:
            try:
                cert_name = getattr(cert, "name", "") or getattr(cert, "id", "").split("/")[-1]

                expires = getattr(cert, "expires_on", None)
                if not expires:
                    continue

                auto_renew = getattr(cert, "policy", None)
                lifetime_actions = getattr(auto_renew, "lifetime_actions", []) if auto_renew else []
                has_auto_renew = any(
                    getattr(getattr(a, "action", None), "action_type", "").lower() == "autorenew"
                    for a in (lifetime_actions or [])
                )

                if has_auto_renew:
                    continue

                now = datetime.now(timezone.utc)
                if hasattr(expires, "tzinfo") and expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)

                days_until_expiry = (expires - now).days

                if 0 <= days_until_expiry <= EXPIRY_THRESHOLD_DAYS:
                    findings.append(
                        {
                            "rule_id": RULE_ID,
                            "rule_name": RULE_NAME,
                            "severity": SEVERITY,
                            "category": CATEGORY,
                            "resource_id": f"{vault.id}/certificates/{cert_name}",
                            "resource_name": cert_name,
                            "resource_type": "Microsoft.KeyVault/vaults/certificates",
                            "description": DESCRIPTION,
                            "remediation": REMEDIATION,
                            "playbook": PLAYBOOK,
                            "frameworks": FRAMEWORKS,
                            "metadata": {
                                "resource_group": rg,
                                "location": getattr(vault, "location", ""),
                                "vault_name": vault_name,
                                "days_until_expiry": days_until_expiry,
                                "expires": expires.isoformat(),
                            },
                        }
                    )

            except Exception as exc:
                logger.error(
                    "AZ-KV-005: error processing cert in vault %s: %s",
                    vault_name,
                    exc,
                )
                continue

    return findings
