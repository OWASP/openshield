"""AZ-NET-018: Private Endpoint target retains public network access."""

import logging
from typing import Any, Dict, List

from scanner.rules._private_link_common import evidence

RULE_ID = "AZ-NET-018"
RULE_NAME = "Private Endpoint Target Retains Public Network Access"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "N/A-NET-018", "NIST": "PR.AC-3", "ISO27001": "A.13.1.1", "SOC2": "CC6.6"}
DESCRIPTION = "A supported PaaS target has a Private Endpoint but still permits public network access."
REMEDIATION = "Validate private connectivity, then disable public network access on the target PaaS resource."
PLAYBOOK = "playbooks/cli/fix_az_net_018.sh"
logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    inventory = azure_client.get_private_link_inventory()
    if inventory is None:
        logger.warning("%s UNKNOWN: Private Endpoint inventory unavailable", RULE_ID)
        return []
    findings = []
    for item in inventory:
        if item.get("public_network_access") is not True:
            continue
        findings.append(_finding(item, {"public_network_access": "Enabled"}, {"public_network_access": "Disabled"}))
    return findings


def _finding(item: Dict[str, Any], observed: Any, expected: Any) -> Dict[str, Any]:
    return {
        "rule_id": RULE_ID,
        "rule_name": RULE_NAME,
        "severity": SEVERITY,
        "category": CATEGORY,
        "resource_id": item.get("endpoint_id", ""),
        "resource_name": item.get("endpoint_name", ""),
        "resource_type": "Microsoft.Network/privateEndpoints",
        "description": DESCRIPTION,
        "remediation": REMEDIATION,
        "playbook": PLAYBOOK,
        "frameworks": FRAMEWORKS,
        "metadata": evidence(item, observed, expected),
    }
