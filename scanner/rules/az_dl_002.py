"""AZ-DL-002: High-speed ExpressRoute Direct link uses a non-XPN MACsec cipher."""

import logging
from typing import Any, Dict, List

from scanner.rules._data_link_common import (
    InventoryState,
    cipher_name,
    enabled_links,
    has_macsec,
    inventory_state,
    resource_identity,
    value,
)

logger = logging.getLogger(__name__)

RULE_ID = "AZ-DL-002"
RULE_NAME = "High-Speed ExpressRoute Direct Link Uses Non-XPN MACsec"
SEVERITY = "MEDIUM"
CATEGORY = "Data Link"
FRAMEWORKS = {"CIS": "N/A-DL-002", "NIST": "PR.DS-2", "ISO27001": "A.8.20", "SOC2": "CC6.7"}
DESCRIPTION = "An enabled ExpressRoute Direct port of 40 Gbps or greater uses a MACsec cipher without XPN."
REMEDIATION = (
    "Confirm both peer devices support an XPN cipher, schedule a maintenance window, update the MACsec "
    "cipher on both ends, and verify link counters and traffic before completing the change."
)
PLAYBOOK = "playbooks/cli/fix_az_dl_002.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Report high-speed enabled links whose configured MACsec cipher is not XPN."""
    ports = azure_client.get_express_route_ports()
    state = inventory_state(ports)
    if state is InventoryState.INDETERMINATE:
        logger.warning("%s: ExpressRoute Direct inventory unavailable; result is indeterminate", RULE_ID)
        return []
    if state is InventoryState.NOT_APPLICABLE:
        logger.info("%s: no ExpressRoute Direct ports; rule is not applicable", RULE_ID)
        return []

    findings: List[Dict[str, Any]] = []
    for port in ports:
        bandwidth = int(value(port, "bandwidth_in_gbps", 0) or 0)
        if bandwidth < 40:
            continue
        for _, link in enabled_links(port):
            if not has_macsec(link):
                continue
            cipher = cipher_name(link)
            if "xpn" in cipher.lower():
                continue
            resource_id, resource_name, link_name = resource_identity(port, link)
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": resource_id,
                    "resource_name": resource_name,
                    "resource_type": "Microsoft.Network/expressRoutePorts",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "bandwidth_in_gbps": bandwidth,
                        "cipher": cipher or "unreported",
                        "link_name": link_name,
                    },
                }
            )
    return findings
