"""AZ-NET-016: Network interface has IP forwarding enabled."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-NET-016"
RULE_NAME = "Network Interface Has IP Forwarding Enabled"
SEVERITY = "MEDIUM"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "N/A-NET-016", "NIST": "SC-7", "ISO27001": "A.8.20", "SOC2": "CC6.6"}
DESCRIPTION = (
    "The network interface has IP forwarding enabled, which disables Azure source and destination checks and "
    "allows the attached workload to forward traffic not addressed to it. This is normally required only for a "
    "documented network virtual appliance or routing function."
)
REMEDIATION = (
    "Confirm that the interface belongs to an approved network virtual appliance. Otherwise disable IP forwarding. "
    "If forwarding is required, document the routing function and restrict its paths with route tables and NSGs."
)
PLAYBOOK = "playbooks/cli/fix_az_net_016.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Report authoritative NIC IP-forwarding state without guessing on API failure."""
    interfaces = azure_client.get_network_interfaces()
    if interfaces is None:
        logger.warning("%s: NIC inventory unavailable; result is indeterminate", RULE_ID)
        return []
    if not interfaces:
        logger.info("%s: no network interfaces; rule is not applicable", RULE_ID)
        return []

    findings: List[Dict[str, Any]] = []
    for interface in interfaces:
        if getattr(interface, "enable_ip_forwarding", None) is not True:
            continue
        resource_id = getattr(interface, "id", "") or ""
        parsed = azure_client.parse_resource_id(resource_id)
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": resource_id,
                "resource_name": getattr(interface, "name", ""),
                "resource_type": "Microsoft.Network/networkInterfaces",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "resource_group": parsed.get("resource_group", ""),
                    "ip_forwarding_enabled": True,
                    "requires_routing_function_review": True,
                },
            }
        )
    return findings
