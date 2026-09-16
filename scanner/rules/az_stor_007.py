"""AZ-STOR-007: Storage account permits a TLS version below TLS 1.2."""

import logging
from typing import Any, Dict, List

from scanner.azure_client import enum_str

logger = logging.getLogger(__name__)

RULE_ID = "AZ-STOR-007"
RULE_NAME = "Storage Account Allows TLS Below 1.2"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {
    "CIS": "N/A-STOR-007",
    "NIST": "N/A-STOR-007",
    "ISO27001": "N/A-STOR-007",
    "SOC2": "N/A-STOR-007",
}
DESCRIPTION = (
    "The storage account permits a minimum TLS version below TLS 1.2. Older "
    "protocols no longer provide an approved transport-security baseline."
)
REMEDIATION = (
    "Set the storage account minimum TLS version to TLS 1.2 or later. Navigate "
    "to Storage Account > Configuration > Minimum TLS version."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_007.sh"

_INSECURE_TLS = {"TLS1_0", "TLS1_1", "1.0", "1.1"}
_SECURE_TLS = {"TLS1_2", "TLS1_3", "1.2", "1.3"}


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Flag accounts with TLS below 1.2 or with an unset minimum TLS version.

    Azure documents an unset minimum_tls_version as TLS 1.0, so None is
    treated as insecure. enum_str() is used to handle SDK enum objects
    (e.g. MinimumTlsVersion.TLS1_0) so they compare correctly against the
    known-insecure set instead of producing a string like
    'MinimumTlsVersion.TLS1_0'.
    """
    findings: List[Dict[str, Any]] = []
    for account in azure_client.get_storage_accounts():
        value = getattr(account, "minimum_tls_version", None)
        if value is None:
            normalized = "TLS1_0"
        else:
            normalized = enum_str(value).strip().upper()
        if normalized not in _INSECURE_TLS:
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
                "metadata": {
                    "minimum_tls_version": str(value),
                    "approved_minimum": "TLS1_2",
                },
            }
        )
    return findings
