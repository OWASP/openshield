"""AZ-NET-009: VPN gateway using outdated IKE version."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-NET-009"
RULE_NAME = "VPN gateway using outdated IKE version"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "9.5", "NIST": "SC-8", "ISO27001": "A.5.14"}
DESCRIPTION = (
    "A VPN gateway is configured to use IKEv1 which is an outdated and less "
    "secure version of the Internet Key Exchange protocol. IKEv1 is vulnerable "
    "to several known attacks and lacks features present in IKEv2 such as "
    "improved authentication and built-in NAT traversal support."
)
REMEDIATION = (
    "Migrate the VPN gateway connection to use IKEv2. Update the VPN gateway "
    "SKU if required and reconfigure all VPN connections to use IKEv2 only. "
    "Coordinate with the remote VPN peer to ensure IKEv2 is supported on both ends."
)
PLAYBOOK = "playbooks/cli/fix_az_net_009.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect VPN gateways using outdated IKEv1."""
    findings: List[Dict[str, Any]] = []

    try:
        from azure.mgmt.network import NetworkManagementClient

        client = NetworkManagementClient(azure_client.credential, azure_client.subscription_id)
        connections = list(client.virtual_network_gateway_connections.list_all())
    except Exception as exc:
        logger.error("Failed to list VPN gateway connections: %s", exc)
        return findings

    for conn in connections:
        ike_version = getattr(conn, "connection_protocol", "") or ""
        if ike_version.upper() == "IKEV1":
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": getattr(conn, "id", ""),
                    "resource_name": getattr(conn, "name", ""),
                    "resource_type": "Microsoft.Network/connections",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "ike_version": ike_version,
                        "location": getattr(conn, "location", ""),
                        "connection_type": getattr(conn, "connection_type", ""),
                    },
                }
            )

    return findings
