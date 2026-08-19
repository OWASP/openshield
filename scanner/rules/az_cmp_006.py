"""AZ-CMP-006: VM Scale Set network profile has a public IP with no associated NSG."""

import logging
from typing import Any, Dict, List, Optional

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

# A subnet reference that can't be resolved (VNet collection failure, missing
# permissions, or an ID this scan never saw) says nothing about whether that
# subnet actually has an NSG — it must not be treated the same as a resolved
# subnet confirmed to have none, or a scan-visibility gap silently turns into
# a false HIGH finding on an already-protected VMSS.
INDETERMINATE_SEVERITY = "LOW"
INDETERMINATE_DESCRIPTION = (
    "A VM Scale Set network interface configuration provisions a public IP address and has no "
    "NSG directly attached, but the NSG state of the subnet it deploys into could not be "
    "verified (virtual network collection failed, the scanning principal lacks "
    "Microsoft.Network/virtualNetworks/read, or the subnet reference could not be matched). "
    "This is not a confirmed violation — the subnet may already be protected by an NSG this "
    "scan could not see."
)
INDETERMINATE_REMEDIATION = (
    "Grant the scanning principal Microsoft.Network/virtualNetworks/read on the relevant "
    "virtual network(s) and re-run the scan to determine the actual subnet NSG state."
)

logger = logging.getLogger(__name__)


def _subnet_nsg_map(azure_client: Any) -> Dict[str, bool]:
    """Map subnet resource ID (lowercased) -> whether that subnet has an NSG attached.

    A VMSS network interface configuration only references its subnet by ID
    (ApiEntityReference); the subnet's own NSG lives on the VirtualNetwork
    resource, so it must be resolved separately to avoid flagging a VMSS that
    is actually protected at the subnet level instead of the NIC level.
    Azure resource IDs are case-insensitive, so keys are normalized to
    lowercase to avoid missing a match on casing differences alone.
    """
    subnet_nsgs: Dict[str, bool] = {}
    for vnet in azure_client.get_virtual_networks():
        for subnet in getattr(vnet, "subnets", []) or []:
            subnet_id = getattr(subnet, "id", None)
            if subnet_id:
                subnet_nsgs[subnet_id.lower()] = bool(getattr(subnet, "network_security_group", None))
    return subnet_nsgs


def _subnet_nsg_status(subnet_nsgs: Dict[str, bool], ip_cfg: Any) -> Optional[bool]:
    """Return True/False if the ip config's subnet NSG state is known, None if unresolved."""
    subnet_ref = getattr(ip_cfg, "subnet", None)
    subnet_id = getattr(subnet_ref, "id", None)
    if not subnet_id:
        return None
    return subnet_nsgs.get(subnet_id.lower())


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

            if not has_public_ip or has_nic_nsg:
                continue

            subnet_statuses = [_subnet_nsg_status(subnet_nsgs, ip_cfg) for ip_cfg in ip_configs]
            has_subnet_nsg = any(status is True for status in subnet_statuses)
            if has_subnet_nsg:
                continue  # protected at the subnet level, compliant

            has_unresolved_subnet = any(status is None for status in subnet_statuses)
            confirmed = not has_unresolved_subnet

            parsed = azure_client.parse_resource_id(vmss_id)
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY if confirmed else INDETERMINATE_SEVERITY,
                    "category": CATEGORY,
                    "resource_id": vmss_id,
                    "resource_name": vmss_name,
                    "resource_type": "Microsoft.Compute/virtualMachineScaleSets",
                    "description": DESCRIPTION if confirmed else INDETERMINATE_DESCRIPTION,
                    "remediation": REMEDIATION if confirmed else INDETERMINATE_REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": parsed.get("resource_group", ""),
                        "location": getattr(vmss, "location", ""),
                        "network_interface_configuration": getattr(net_config, "name", ""),
                        "determination": "non_compliant" if confirmed else "indeterminate",
                    },
                }
            )
            break  # one finding per VMSS is sufficient

    return findings
