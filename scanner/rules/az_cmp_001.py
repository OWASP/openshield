"""AZ-CMP-001: Virtual machine has a public IP with no associated NSG."""

import logging
from typing import Any, Dict, List, Optional

RULE_ID = "AZ-CMP-001"
RULE_NAME = "VM with Public IP and No Associated NSG on Network Interface"
SEVERITY = "HIGH"
CATEGORY = "Compute"
FRAMEWORKS = {"CIS": "7.1", "NIST": "PR.AC-3", "ISO27001": "A.13.1.1"}
DESCRIPTION = (
    "A virtual machine has a public IP address assigned to its network interface "
    "but no Network Security Group protecting that interface. Without an NSG, "
    "all inbound ports are open to the internet by default, creating an unrestricted "
    "attack surface."
)
REMEDIATION = (
    "Associate an NSG with the VM's network interface or its subnet that allows "
    "only required inbound traffic. Remove the public IP if internet access is not needed "
    "and use Azure Bastion or a VPN gateway for administrative access."
)
PLAYBOOK = "playbooks/cli/fix_az_cmp_001.sh"

# An unresolvable subnet says nothing about whether it actually has an NSG, so
# it must not be read as "confirmed unprotected" and carry the same HIGH
# severity as a real finding -- that would let a permissions gap or a
# transient API failure masquerade as a genuine misconfiguration. Mirrors the
# same confirmed/indeterminate split already used by AZ-CMP-002.
INDETERMINATE_SEVERITY = "LOW"
INDETERMINATE_DESCRIPTION = (
    "A virtual machine has a public IP address assigned to its network interface with no "
    "NSG on the interface itself, and the subnet backing at least one IP configuration "
    "could not be resolved, so subnet-level protection could not be verified. This is not "
    "a confirmed violation -- the scanning principal could not resolve the Subnet resource "
    "(missing Microsoft.Network/virtualNetworks/subnets/read, transient API failure, or the "
    "subnet no longer exists)."
)
INDETERMINATE_REMEDIATION = (
    "Grant the scanning principal Microsoft.Network/virtualNetworks/subnets/read on the "
    "affected subnet(s) and re-run the scan to determine whether the subnet actually has "
    "an NSG attached."
)

logger = logging.getLogger(__name__)


def _subnet_nsg_status(azure_client: Any, nic: Any) -> Optional[bool]:
    """Resolve whether any subnet backing this NIC's IP configurations carries its own NSG.

    A NIC without a NIC-level NSG can still be protected by an NSG attached
    to its subnet - that is a common, valid Azure pattern, not a
    misconfiguration.

    Returns:
        True  - at least one backing subnet was resolved and has an NSG (protected).
        False - every backing subnet was resolved and none has an NSG (confirmed unprotected).
        None  - at least one backing subnet could not be resolved (missing ID, permissions,
                SDK error) and none of the resolvable ones confirmed protection, so
                subnet-level protection cannot be confirmed either way.
    """
    unresolved = False
    for ip_cfg in getattr(nic, "ip_configurations", []) or []:
        subnet_ref = getattr(ip_cfg, "subnet", None)
        subnet_id = getattr(subnet_ref, "id", None)
        if not subnet_id:
            unresolved = True
            continue

        subnet = azure_client.get_subnet(subnet_id)
        if subnet is None:
            unresolved = True
            continue

        if getattr(subnet, "network_security_group", None):
            return True

    return None if unresolved else False


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect VMs whose NIC has a public IP but no NSG at the NIC or subnet level."""
    findings: List[Dict[str, Any]] = []

    for vm in azure_client.get_virtual_machines():
        network_profile = getattr(vm, "network_profile", None)
        if not network_profile:
            continue

        # One finding per VM is enough, but an indeterminate result on an
        # earlier NIC must never suppress evaluation of a later NIC - a
        # confirmed HIGH elsewhere on the same VM must not be downgraded to
        # LOW just because it was reached second. Keep the worst evaluated
        # result across all of this VM's NICs and only stop early once a
        # confirmed violation is found (nothing can outrank it).
        vm_finding: Optional[Dict[str, Any]] = None

        for nic_ref in getattr(network_profile, "network_interfaces", []) or []:
            nic_id = getattr(nic_ref, "id", "")
            if not nic_id:
                continue

            parsed = azure_client.parse_resource_id(nic_id)
            resource_group = parsed.get("resource_group", "")
            nic_name = parsed.get("name", "")
            if not resource_group or not nic_name:
                continue

            nic = azure_client.get_network_interface(resource_group, nic_name)
            if not nic:
                continue

            has_public_ip = any(
                getattr(ip_cfg, "public_ip_address", None) for ip_cfg in (getattr(nic, "ip_configurations", []) or [])
            )
            has_nic_nsg = bool(getattr(nic, "network_security_group", None))

            subnet_status: Optional[bool] = None
            if has_public_ip and not has_nic_nsg:
                subnet_status = _subnet_nsg_status(azure_client, nic)

            if has_public_ip and not has_nic_nsg and subnet_status is not True:
                confirmed = subnet_status is False
                if vm_finding is not None and not confirmed:
                    # Already have a finding for this VM (confirmed or
                    # indeterminate) and this NIC only adds another
                    # indeterminate one - it can't raise the severity, so
                    # keep the existing finding rather than overwrite it.
                    continue
                vm_finding = {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY if confirmed else INDETERMINATE_SEVERITY,
                    "category": CATEGORY,
                    "resource_id": vm.id,
                    "resource_name": vm.name,
                    "resource_type": "Microsoft.Compute/virtualMachines",
                    "description": DESCRIPTION if confirmed else INDETERMINATE_DESCRIPTION,
                    "remediation": REMEDIATION if confirmed else INDETERMINATE_REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "nic_id": nic_id,
                        "nic_name": nic_name,
                        "nic_nsg_attached": has_nic_nsg,
                        "subnet_nsg_attached": False if confirmed else None,
                        "determination": "non_compliant" if confirmed else "indeterminate",
                    },
                }
                if confirmed:
                    break  # a confirmed HIGH can't be outranked by another NIC on this VM

        if vm_finding is not None:
            findings.append(vm_finding)

    return findings
