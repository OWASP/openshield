"""AZ-CMP-006: VM Scale Set network profile has a public IP with no associated NSG."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-CMP-006"
RULE_NAME = "VM Scale Set with Public IP and No Associated NSG on Network Interface"
SEVERITY = "HIGH"
CATEGORY = "Compute"
FRAMEWORKS = {"CIS": "N/A-CMP-006", "NIST": "PR.AC-3", "ISO27001": "A.13.1.1", "SOC2": "CC6.6"}
DESCRIPTION = (
    "A VM Scale Set network interface configuration provisions a public IP address "
    "for its instances but has no Network Security Group protecting that interface, "
    "either directly or via the subnet it deploys into. Without an NSG, all inbound "
    "ports are open to the internet by default on every instance created from this "
    "scale set, creating an unrestricted attack surface."
)
REMEDIATION = (
    "Attach an NSG to the scale set's network interface configuration or to the "
    "subnet it deploys into, with rules that allow only required inbound traffic. "
    "Remove the public IP configuration if internet access is not needed and use "
    "Azure Bastion or a load balancer for administrative/application access instead."
)
PLAYBOOK = "playbooks/cli/fix_az_cmp_006.sh"

logger = logging.getLogger(__name__)


def _subnet_nsg_map(azure_client: Any) -> Dict[str, bool]:
    """Map subnet resource ID -> whether that subnet has an NSG attached.

    A VMSS network interface configuration only references its subnet by ID
    (ApiEntityReference); the subnet's own NSG lives on the VirtualNetwork
    resource, so it must be resolved separately to avoid flagging a VMSS that
    is actually protected at the subnet level instead of the NIC level.
    """
    subnet_nsgs: Dict[str, bool] = {}
    for vnet in azure_client.get_virtual_networks():
        for subnet in getattr(vnet, "subnets", []) or []:
            subnet_id = getattr(subnet, "id", None)
            if subnet_id:
                subnet_nsgs[subnet_id] = bool(getattr(subnet, "network_security_group", None))
    return subnet_nsgs


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect VM Scale Sets whose network interface configuration has a public IP
    but no NSG protecting it, at either the NIC or the subnet level."""
    findings: List[Dict[str, Any]] = []
    subnet_nsgs = _subnet_nsg_map(azure_client)

    for vmss in azure_client.get_virtual_machine_scale_sets():
        vmss_id = getattr(vmss, "id", "")
        vmss_name = getattr(vmss, "name", "")
        if not vmss_id or not vmss_name:
            continue

        vm_profile = getattr(vmss, "virtual_machine_profile", None)
        network_profile = getattr(vm_profile, "network_profile", None)
        if not network_profile:
            continue

        net_configs = getattr(network_profile, "network_interface_configurations", []) or []
        for net_config in net_configs:
            ip_configs = getattr(net_config, "ip_configurations", []) or []
            has_public_ip = any(getattr(ip_cfg, "public_ip_address_configuration", None) for ip_cfg in ip_configs)
            has_nic_nsg = bool(getattr(net_config, "network_security_group", None))
            has_subnet_nsg = any(
                subnet_nsgs.get(getattr(getattr(ip_cfg, "subnet", None), "id", None), False) for ip_cfg in ip_configs
            )

            if has_public_ip and not has_nic_nsg and not has_subnet_nsg:
                parsed = azure_client.parse_resource_id(vmss_id)
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "category": CATEGORY,
                        "resource_id": vmss_id,
                        "resource_name": vmss_name,
                        "resource_type": "Microsoft.Compute/virtualMachineScaleSets",
                        "description": DESCRIPTION,
                        "remediation": REMEDIATION,
                        "playbook": PLAYBOOK,
                        "frameworks": FRAMEWORKS,
                        "metadata": {
                            "resource_group": parsed.get("resource_group", ""),
                            "location": getattr(vmss, "location", ""),
                            "network_interface_configuration": getattr(net_config, "name", ""),
                        },
                    }
                )
                break  # one finding per VMSS is sufficient

    return findings
