"""AZ-CMP-007: VM management ports open without Just-In-Time (JIT) VM access."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-CMP-007"
RULE_NAME = "VM Management Ports Open Without Just-In-Time (JIT) Access"
SEVERITY = "MEDIUM"
CATEGORY = "Compute"
FRAMEWORKS = {
    "CIS": "N/A-CMP-007",
    "NIST": "PR.AC-3",
    "ISO27001": "A.13.1.1",
    "SOC2": "CC6.6",
}
DESCRIPTION = (
    "A virtual machine has management ports (SSH 22 / RDP 3389) allowed inbound "
    "from the internet by a network security group (on the NIC or its subnet), and no Microsoft Defender "
    "for Cloud Just-In-Time (JIT) VM access policy covers those ports. The ports "
    "are therefore open on a standing basis instead of only during an approved, "
    "time-boxed request, leaving them continuously exposed to scanning and "
    "brute-force attacks. VMs with no management ports open are not applicable."
)
REMEDIATION = (
    "Enable Just-In-Time VM access in Microsoft Defender for Cloud for the affected "
    "VM and ports (or `az security jit-policy create`), so management ports are only "
    "opened for an approved, time-limited window. Alternatively restrict the NSG "
    "rule to trusted source ranges or use Azure Bastion for administrative access."
)
PLAYBOOK = "playbooks/cli/fix_az_cmp_007.sh"

logger = logging.getLogger(__name__)

# Inbound management ports this rule cares about (SSH, RDP).
_MANAGEMENT_PORTS = ("22", "3389")
# Source specifications that mean "reachable from anywhere on the internet".
_OPEN_SOURCES = {"*", "0.0.0.0/0", "Internet", "Any"}


def _spec_covers_port(spec: str, port: int) -> bool:
    """True if an NSG destination-port spec covers ``port``.

    A spec is ``*`` (all ports), a single number (``22``), or an inclusive range
    (``20-30``). Ranges are the case the earlier exact-match logic missed: a rule
    with ``destination_port_range = "20-30"`` exposes SSH but read as closed.
    """
    spec = spec.strip()
    if not spec:
        return False
    if spec == "*":
        return True
    if "-" in spec:
        low, _, high = spec.partition("-")
        try:
            return int(low) <= port <= int(high)
        except ValueError:
            return False
    try:
        return int(spec) == port
    except ValueError:
        return False


def _rule_allows_port_from_any(rule: Any, port: str) -> bool:
    """True if an NSG security rule allows inbound traffic on ``port`` from any source."""
    if str(getattr(rule, "direction", "")).lower() != "inbound":
        return False
    if str(getattr(rule, "access", "")).lower() != "allow":
        return False

    source = getattr(rule, "source_address_prefix", "") or ""
    source_prefixes = getattr(rule, "source_address_prefixes", []) or []
    if source not in _OPEN_SOURCES and not any(s in _OPEN_SOURCES for s in source_prefixes):
        return False

    port_int = int(port)
    dest_specs = [str(getattr(rule, "destination_port_range", "") or "")]
    dest_specs.extend(str(item) for item in (getattr(rule, "destination_port_ranges", []) or []))
    return any(_spec_covers_port(spec, port_int) for spec in dest_specs)


def _jit_coverage(policies: List[Any]) -> Dict[str, set]:
    """Map lower-cased VM resource id -> set of JIT-covered management ports.

    A port covered as ``*`` (or the literal management port number) counts as
    covered. An empty ``policies`` list yields an empty map (genuinely no JIT
    coverage); the caller handles the indeterminate (``None``) case separately.
    """
    coverage: Dict[str, set] = {}
    for policy in policies or []:
        for jit_vm in getattr(policy, "virtual_machines", []) or []:
            vm_id = (getattr(jit_vm, "id", "") or "").lower()
            if not vm_id:
                continue
            ports = {str(getattr(p, "number", "")) for p in (getattr(jit_vm, "ports", []) or [])}
            coverage.setdefault(vm_id, set()).update(ports)
    return coverage


def _applicable_nsgs(
    azure_client: Any,
    vm: Any,
    nsg_by_id: Dict[str, Any],
    nsg_by_subnet_id: Dict[str, Any],
) -> List[Any]:
    """Every NSG that governs this VM's inbound traffic — NIC-level *and* subnet-level.

    An NSG can be attached directly to the NIC or to the NIC's subnet. A VM with
    no NIC-level NSG can still be exposed through its subnet NSG, so both paths
    must be considered or the rule reports a false NOT_APPLICABLE.
    """
    nsgs: List[Any] = []
    seen: set = set()
    network_profile = getattr(vm, "network_profile", None)
    if not network_profile:
        return nsgs

    def _add(nsg: Any) -> None:
        if nsg is None:
            return
        key = (getattr(nsg, "id", "") or "").lower() or id(nsg)
        if key not in seen:
            seen.add(key)
            nsgs.append(nsg)

    for nic_ref in getattr(network_profile, "network_interfaces", []) or []:
        parsed = azure_client.parse_resource_id(getattr(nic_ref, "id", ""))
        resource_group = parsed.get("resource_group", "")
        nic_name = parsed.get("name", "")
        if not resource_group or not nic_name:
            continue
        nic = azure_client.get_network_interface(resource_group, nic_name)
        if not nic:
            continue
        nic_nsg_ref = getattr(nic, "network_security_group", None)
        _add(nsg_by_id.get((getattr(nic_nsg_ref, "id", "") or "").lower()))
        for ip_config in getattr(nic, "ip_configurations", []) or []:
            subnet = getattr(ip_config, "subnet", None)
            _add(nsg_by_subnet_id.get((getattr(subnet, "id", "") or "").lower()))
    return nsgs


def _open_management_ports(
    azure_client: Any,
    vm: Any,
    nsg_by_id: Dict[str, Any],
    nsg_by_subnet_id: Dict[str, Any],
) -> set:
    """Return the management ports open to the internet on any NSG that governs the VM."""
    open_ports: set = set()
    for nsg in _applicable_nsgs(azure_client, vm, nsg_by_id, nsg_by_subnet_id):
        for security_rule in getattr(nsg, "security_rules", []) or []:
            for port in _MANAGEMENT_PORTS:
                if _rule_allows_port_from_any(security_rule, port):
                    open_ports.add(port)
    return open_ports


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Flag VMs with internet-open management ports not covered by a JIT policy.

    A VM is flagged only when at least one management port (22/3389) is open to
    the internet through its NIC's NSG *and* that port is not covered by a
    Defender for Cloud JIT policy for that VM. VMs with no management ports open
    are treated as NOT_APPLICABLE and are not flagged.
    """
    findings: List[Dict[str, Any]] = []

    policies = azure_client.get_jit_network_access_policies()
    if policies is None:
        # Defender for Cloud could not be queried: coverage is indeterminate, so
        # we cannot assert a VM has "no JIT policy". Skip rather than false-positive.
        return findings

    coverage = _jit_coverage(policies)
    all_nsgs = azure_client.get_network_security_groups() or []
    nsg_by_id = {(getattr(nsg, "id", "") or "").lower(): nsg for nsg in all_nsgs}
    nsg_by_subnet_id: Dict[str, Any] = {}
    for nsg in all_nsgs:
        for subnet in getattr(nsg, "subnets", []) or []:
            subnet_id = (getattr(subnet, "id", "") or "").lower()
            if subnet_id:
                nsg_by_subnet_id[subnet_id] = nsg

    for vm in azure_client.get_virtual_machines():
        open_ports = _open_management_ports(azure_client, vm, nsg_by_id, nsg_by_subnet_id)
        if not open_ports:
            continue  # NOT_APPLICABLE: no management ports exposed

        covered_ports = coverage.get((getattr(vm, "id", "") or "").lower(), set())
        if "*" in covered_ports:
            uncovered = set()
        else:
            uncovered = {port for port in open_ports if port not in covered_ports}
        if not uncovered:
            continue  # every exposed port is covered by a JIT policy

        parsed = azure_client.parse_resource_id(getattr(vm, "id", ""))
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": getattr(vm, "id", ""),
                "resource_name": getattr(vm, "name", None) or parsed.get("name", ""),
                "resource_type": "Microsoft.Compute/virtualMachines",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "open_management_ports": sorted(open_ports),
                    "uncovered_ports": sorted(uncovered),
                    "jit_policy_present": bool(covered_ports),
                },
            }
        )

    return findings
