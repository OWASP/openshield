"""AZ-NET-010: Subnet with no network security group attached."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-NET-010"
RULE_NAME = "Subnet with no network security group attached"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "9.10", "NIST": "SC-7", "ISO27001": "A.8.20"}
DESCRIPTION = (
    "A subnet exists without a Network Security Group attached. Without an NSG "
    "at the subnet level, all resources deployed into that subnet have no network "
    "layer access control. Any VM or service in the subnet is reachable from "
    "other subnets and potentially the internet with no filtering in place."
)
REMEDIATION = (
    "Create and attach an NSG to the subnet with rules that follow the principle "
    "of least privilege. Define explicit allow rules for required traffic and "
    "deny everything else. Apply NSGs at both the subnet and NIC level for "
    "defence in depth."
)
PLAYBOOK = "playbooks/cli/fix_az_net_010.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect subnets with no NSG attached."""
    findings: List[Dict[str, Any]] = []

    try:
        from azure.mgmt.network import NetworkManagementClient

        client = NetworkManagementClient(azure_client.credential, azure_client.subscription_id)
        vnets = list(client.virtual_networks.list_all())
    except Exception as exc:
        logger.error("Failed to list virtual networks: %s", exc)
        return findings

    for vnet in vnets:
        for subnet in getattr(vnet, "subnets", []) or []:
            name = getattr(subnet, "name", "")
            if name in ("GatewaySubnet", "AzureFirewallSubnet", "AzureBastionSubnet"):
                continue
            nsg = getattr(subnet, "network_security_group", None)
            if not nsg:
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "category": CATEGORY,
                        "resource_id": getattr(subnet, "id", ""),
                        "resource_name": name,
                        "resource_type": "Microsoft.Network/virtualNetworks/subnets",
                        "description": DESCRIPTION,
                        "remediation": REMEDIATION,
                        "playbook": PLAYBOOK,
                        "frameworks": FRAMEWORKS,
                        "metadata": {
                            "vnet_name": getattr(vnet, "name", ""),
                            "vnet_id": getattr(vnet, "id", ""),
                            "address_prefix": getattr(subnet, "address_prefix", ""),
                        },
                    }
                )

    return findings
