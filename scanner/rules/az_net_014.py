"""AZ-NET-014: VNet peering configured without gateway transit restrictions."""

from typing import Any, Dict, List

RULE_ID = "AZ-NET-014"
RULE_NAME = "VNet Peering Configured Without Gateway Transit Restrictions"
SEVERITY = "MEDIUM"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "6.6", "NIST": "PR.AC-5", "ISO27001": "A.8.20", "SOC2": "CC6.6"}
DESCRIPTION = (
    "A Virtual Network peering connection has gateway transit enabled. "
    "Enabling allowGatewayTransit or useRemoteGateways on a peering "
    "connection allows traffic to flow between network segments through "
    "shared gateways, potentially enabling lateral movement between "
    "network zones that should be isolated from each other."
)
REMEDIATION = (
    "Review all VNet peering connections and disable allowGatewayTransit "
    "and useRemoteGateways unless explicitly required and documented. "
    "Ensure peering connections follow the principle of least privilege "
    "and only permit the minimum required traffic between networks."
)
PLAYBOOK = "playbooks/cli/fix_az_net_014.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for vnet in azure_client.get_virtual_networks():
        parsed = azure_client.parse_resource_id(vnet.id)
        resource_group = parsed["resource_group"]
        vnet_name = parsed["name"]
        peerings = azure_client.get_vnet_peerings(resource_group, vnet_name)
        for peering in peerings:
            allow_gateway_transit = getattr(peering, "allow_gateway_transit", False)
            use_remote_gateways = getattr(peering, "use_remote_gateways", False)
            if allow_gateway_transit or use_remote_gateways:
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "category": CATEGORY,
                        "resource_id": vnet.id,
                        "resource_name": vnet_name,
                        "resource_type": "Microsoft.Network/virtualNetworks",
                        "description": DESCRIPTION,
                        "remediation": REMEDIATION,
                        "playbook": PLAYBOOK,
                        "frameworks": FRAMEWORKS,
                        "metadata": {
                            "resource_group": resource_group,
                            "peering_name": getattr(peering, "name", "unknown"),
                        },
                    }
                )
    return findings
