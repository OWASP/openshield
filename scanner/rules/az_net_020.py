"""AZ-NET-020: Private Endpoint lacks a Private DNS zone group."""

import logging
from typing import Any, Dict, List

from scanner.rules._private_link_common import evidence

RULE_ID = "AZ-NET-020"
RULE_NAME = "Private Endpoint Lacks Private DNS Zone Association"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "N/A-NET-020", "NIST": "PR.AC-5", "ISO27001": "A.13.1.1", "SOC2": "CC6.6"}
DESCRIPTION = "An approved Private Endpoint has no associated Private DNS zone group."
REMEDIATION = (
    "Associate the service's documented privatelink DNS zone with the Private Endpoint "
    "and link it to the consuming VNet."
)
PLAYBOOK = "playbooks/cli/fix_az_net_020.sh"
logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    inventory = azure_client.get_private_link_inventory()
    if inventory is None:
        logger.warning("%s UNKNOWN: Private Endpoint inventory unavailable", RULE_ID)
        return []
    findings = []
    for item in inventory:
        zones = item.get("dns_zone_ids")
        if zones is None:
            logger.warning("%s UNKNOWN for %s: DNS zone groups unavailable", RULE_ID, item.get("endpoint_name"))
            continue
        if str(item.get("connection_status", "")).lower() != "approved" or zones:
            continue
        findings.append(
            {
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
                "metadata": evidence(item, {"private_dns_zone_ids": []}, {"private_dns_zone_association": "Present"}),
            }
        )
    return findings
