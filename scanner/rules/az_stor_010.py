"""AZ-STOR-010: Storage account reachable publicly with no approved private endpoint."""

import logging
from typing import Any, Dict, List

from scanner.azure_client import enum_str

logger = logging.getLogger(__name__)

RULE_ID = "AZ-STOR-010"
RULE_NAME = "Storage Account Missing Private Endpoint"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {"CIS": "N/A-STOR-010", "NIST": "PR.AC-5", "ISO27001": "A.13.1.3", "SOC2": "CC6.6"}
DESCRIPTION = (
    "A storage account reachable over the public network has no approved Private "
    "Endpoint connection, so its blob/file/queue/table endpoints stay reachable from "
    "the internet. Traffic does not remain inside a private VNet, widening the attack "
    "surface for unauthorized access and data exfiltration."
)
REMEDIATION = (
    "Create a Private Endpoint for the storage account and approve the connection "
    "(`az network private-endpoint create ...`), then set the account's public network "
    "access to Disabled (or Selected networks) so traffic flows only over the private "
    "IP inside the VNet."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_010.sh"


def _has_approved_private_endpoint(account: Any) -> bool:
    """True if the account has at least one Private Endpoint connection in the Approved state."""
    for connection in getattr(account, "private_endpoint_connections", None) or []:
        state = getattr(connection, "private_link_service_connection_state", None)
        if enum_str(getattr(state, "status", None)).lower() == "approved":
            return True
    return False


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Flag publicly reachable storage accounts with no approved Private Endpoint.

    A storage account whose ``public_network_access`` is already ``Disabled`` is
    network-isolated regardless of private endpoints and is treated as
    NOT_APPLICABLE, so the rule does not raise a false finding against an account
    that is closed to the public network by another means.
    """
    findings: List[Dict[str, Any]] = []

    for account in azure_client.get_storage_accounts():
        if enum_str(getattr(account, "public_network_access", None)).lower() == "disabled":
            continue
        if _has_approved_private_endpoint(account):
            continue

        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": getattr(account, "id", ""),
                "resource_name": getattr(account, "name", ""),
                "resource_type": "Microsoft.Storage/storageAccounts",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "public_network_access": enum_str(getattr(account, "public_network_access", None)) or "unspecified",
                    "private_endpoint_connections": len(getattr(account, "private_endpoint_connections", None) or []),
                },
            }
        )

    return findings
