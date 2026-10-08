"""AZ-NET-017: User-defined default route sends traffic directly to the Internet."""

import logging
from typing import Any, Dict, List

from scanner.azure_client import enum_str

RULE_ID = "AZ-NET-017"
RULE_NAME = "User-Defined Default Route Uses Direct Internet Next Hop"
SEVERITY = "MEDIUM"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "N/A-NET-017", "NIST": "SC-7", "ISO27001": "A.8.20", "SOC2": "CC6.6"}
DESCRIPTION = (
    "A user-defined IPv4 or IPv6 default route explicitly sends traffic to the Internet next hop. This bypasses "
    "a virtual appliance or virtual network gateway that would otherwise provide controlled egress inspection."
)
REMEDIATION = (
    "Review the subnet egress design. Remove the direct Internet default route or change its next hop to the approved "
    "Azure Firewall, network virtual appliance, or virtual network gateway."
)
PLAYBOOK = "playbooks/cli/fix_az_net_017.sh"

logger = logging.getLogger(__name__)
DEFAULT_PREFIXES = {"0.0.0.0/0", "::/0"}


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Report explicit default Internet UDRs and preserve failed inventory as indeterminate."""
    route_tables = azure_client.get_route_tables()
    if route_tables is None:
        logger.warning("%s: route-table inventory unavailable; result is indeterminate", RULE_ID)
        return []
    if not route_tables:
        logger.info("%s: no route tables; rule is not applicable", RULE_ID)
        return []

    findings: List[Dict[str, Any]] = []
    for route_table in route_tables:
        for route in getattr(route_table, "routes", None) or []:
            address_prefix = (getattr(route, "address_prefix", "") or "").strip()
            next_hop_type = enum_str(getattr(route, "next_hop_type", ""))
            if address_prefix not in DEFAULT_PREFIXES or next_hop_type.lower() != "internet":
                continue
            route_table_id = getattr(route_table, "id", "") or ""
            route_id = getattr(route, "id", "") or route_table_id
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": route_id,
                    "resource_name": getattr(route, "name", "") or getattr(route_table, "name", ""),
                    "resource_type": "Microsoft.Network/routeTables/routes",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "route_table_id": route_table_id,
                        "route_table_name": getattr(route_table, "name", ""),
                        "address_prefix": address_prefix,
                        "next_hop_type": next_hop_type,
                    },
                }
            )
    return findings
