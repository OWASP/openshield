"""AZ-NET-002: NSG allows unrestricted inbound RDP (port 3389) from 0.0.0.0/0."""

from typing import Any, Dict, List

RULE_ID = "AZ-NET-002"
RULE_NAME = "NSG Allows Unrestricted Inbound RDP from Any Source"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "6.3", "NIST": "PR.AC-3", "ISO27001": "A.8.20"}
DESCRIPTION = (
    "The Network Security Group has an Allow rule for inbound TCP port 3389 (RDP) "
    "from any source address (0.0.0.0/0, *, or Internet). Exposing RDP to the "
    "internet is one of the most common initial access vectors for ransomware and "
    "credential-stuffing attacks."
)
REMEDIATION = (
    "Remove or restrict the inbound RDP rule to known trusted IP ranges only. "
    "Consider using Azure Bastion for privileged Windows access instead of direct RDP exposure."
)
PLAYBOOK = "playbooks/cli/fix_az_net_002.sh"

_OPEN_SOURCES = {"*", "0.0.0.0/0", "Internet", "Any"}


def _rule_allows_port_from_any(rule: Any, port: str) -> bool:
    """Return True if a security rule allows inbound traffic on the given port from any source."""
    if str(getattr(rule, "direction", "")).lower() != "inbound":
        return False
    if str(getattr(rule, "access", "")).lower() != "allow":
        return False

    source = getattr(rule, "source_address_prefix", "") or ""
    source_prefixes = getattr(rule, "source_address_prefixes", []) or []
    source_open = source in _OPEN_SOURCES or any(s in _OPEN_SOURCES for s in source_prefixes)

    if not source_open:
        return False

    dest_range = str(getattr(rule, "destination_port_range", "") or "")
    dest_ranges = [str(r) for r in (getattr(rule, "destination_port_ranges", []) or [])]
    return dest_range in (port, "*") or port in dest_ranges or "*" in dest_ranges


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect NSGs with Allow-inbound-RDP-from-any rules."""
    findings: List[Dict[str, Any]] = []

    for nsg in azure_client.get_network_security_groups():
        for rule in getattr(nsg, "security_rules", []) or []:
            if _rule_allows_port_from_any(rule, "3389"):
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "category": CATEGORY,
                        "resource_id": nsg.id,
                        "resource_name": nsg.name,
                        "resource_type": "Microsoft.Network/networkSecurityGroups",
                        "description": DESCRIPTION,
                        "remediation": REMEDIATION,
                        "playbook": PLAYBOOK,
                        "frameworks": FRAMEWORKS,
                        "metadata": {"offending_rule": rule.name},
                    }
                )
                break  # one finding per NSG is enough

    return findings
