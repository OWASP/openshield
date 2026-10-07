"""AZ-DL-001: Enabled ExpressRoute Direct link has no MACsec configuration."""

import logging
from typing import Any, Dict, List

from scanner.rules._data_link_common import (
    InventoryState,
    enabled_links,
    has_macsec,
    inventory_state,
    resource_identity,
)

logger = logging.getLogger(__name__)

RULE_ID = "AZ-DL-001"
RULE_NAME = "ExpressRoute Direct Link Does Not Use MACsec"
SEVERITY = "HIGH"
CATEGORY = "Data Link"
FRAMEWORKS = {"CIS": "N/A-DL-001", "NIST": "PR.DS-2", "ISO27001": "A.8.20", "SOC2": "CC6.7"}
DESCRIPTION = "An enabled ExpressRoute Direct Ethernet link does not have a MACsec configuration."
REMEDIATION = (
    "Plan a maintenance window, store CAK and CKN values in Azure Key Vault, then enable MACsec on both "
    "ends of the ExpressRoute Direct link. Confirm connectivity before retiring the previous configuration."
)
PLAYBOOK = "playbooks/cli/fix_az_dl_001.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Report enabled links without MACsec and preserve API failures as indeterminate."""
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
        for _, link in enabled_links(port):
            if has_macsec(link):
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
                    "metadata": {"link_name": link_name},
                }
            )
    return findings
