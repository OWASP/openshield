"""AZ-NET-013: Azure Firewall not enabled on Virtual Network."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-NET-013"
RULE_NAME = "Azure Firewall Not Enabled on Virtual Network"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {
    "CIS": "6.4",
    "NIST": "PR.AC-5",
    "ISO27001": "A.8.20",
    "SOC2": "CC6.6",
}
DESCRIPTION = (
    "The virtual network has no Azure Firewall deployed or associated. "
    "Relying only on Network Security Groups leaves the network without a "
    "centralized perimeter inspection, logging, and threat-filtering layer. "
    "Azure Firewall provides stateful traffic inspection, FQDN filtering, "
    "threat intelligence, and centralized network logging that NSGs alone "
    "cannot offer."
)
REMEDIATION = (
    "Deploy an Azure Firewall into an 'AzureFirewallSubnet' within the "
    "virtual network (or a peered hub network) and route traffic through it. "
    "See playbooks/cli/fix_az_net_013.sh for the Azure CLI steps."
)
PLAYBOOK = "playbooks/cli/fix_az_net_013.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect virtual networks that have no Azure Firewall associated."""
    findings: List[Dict[str, Any]] = []

    firewalls = azure_client.get_all_azure_firewalls()
    # None means the firewall listing failed (permissions/SDK error). Without
    # it we cannot tell which VNets are protected, so skip to avoid flagging
    # every VNet as a false positive.
    if firewalls is None:
        logger.warning("AZ-NET-013 skipped: unable to list Azure Firewalls - cannot determine VNet protection status.")
        return findings

    protected_vnet_ids = set()
    for firewall in firewalls:
        for ip_config in getattr(firewall, "ip_configurations", None) or []:
            subnet = getattr(ip_config, "subnet", None)
            subnet_id = getattr(subnet, "id", "") or ""
            if "/subnets/" in subnet_id:
                vnet_id = subnet_id.rsplit("/subnets/", 1)[0]
                protected_vnet_ids.add(vnet_id.lower())

    for vnet in azure_client.get_virtual_networks():
        vnet_id = getattr(vnet, "id", "") or ""
        if vnet_id.lower() in protected_vnet_ids:
            continue
        parsed = azure_client.parse_resource_id(vnet_id)
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": vnet_id,
                "resource_name": getattr(vnet, "name", ""),
                "resource_type": "Microsoft.Network/virtualNetworks",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "location": getattr(vnet, "location", ""),
                    "resource_group": parsed.get("resource_group", ""),
                },
            }
        )

    return findings
