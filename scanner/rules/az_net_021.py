"""AZ-NET-021: Private Endpoint ARM DNS configuration reports only public addresses."""

import logging
from typing import Any, Dict, List

from scanner.rules._private_link_common import evidence, private_address

RULE_ID = "AZ-NET-021"
RULE_NAME = "Private Endpoint DNS Configuration Reports Only Public Addresses"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "N/A-NET-021", "NIST": "PR.AC-5", "ISO27001": "A.13.1.1", "SOC2": "CC6.6"}
DESCRIPTION = (
    "Azure's Private Endpoint custom DNS configuration reports an FQDN with only public IP addresses. "
    "This control validates ARM configuration evidence; it does not test effective DNS resolution from a VNet "
    "workload or an on-premises resolver."
)
REMEDIATION = (
    "Correct the Private Endpoint DNS configuration so its FQDN is associated with the allocated private IP, "
    "then separately validate effective resolution from every relevant VNet and on-premises resolver path."
)
PLAYBOOK = "playbooks/cli/fix_az_net_021.sh"
logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    inventory = azure_client.get_private_link_inventory()
    if inventory is None:
        logger.warning("%s UNKNOWN: Private Endpoint inventory unavailable", RULE_ID)
        return []
    findings = []
    for item in inventory:
        configs = item.get("dns_configs")
        if not configs:
            logger.warning(
                "%s UNKNOWN for %s: custom DNS configuration unavailable", RULE_ID, item.get("endpoint_name")
            )
            continue
        bad = []
        for config in configs:
            addresses = [private_address(value) for value in config.get("ip_addresses", [])]
            if (
                config.get("fqdn")
                and addresses
                and all(value is not None for value in addresses)
                and not any(addresses)
            ):
                bad.append(config)
        if not bad:
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
                "metadata": evidence(
                    item,
                    {"non_private_custom_dns_configs": bad},
                    {"custom_dns_config": "FQDN associated with a private IP address"},
                ),
            }
        )
    return findings
