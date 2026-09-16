"""AZ-NET-019: Private Endpoint connection is not approved."""

import logging
from typing import Any, Dict, List

from scanner.rules._private_link_common import evidence

RULE_ID = "AZ-NET-019"
RULE_NAME = "Private Endpoint Connection Is Not Approved"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "N/A-NET-019", "NIST": "PR.AC-5", "ISO27001": "A.13.1.1", "SOC2": "CC6.6"}
DESCRIPTION = (
    "A Private Endpoint connection is pending, rejected, or disconnected and cannot provide the intended private path."
)
REMEDIATION = (
    "Approve the intended connection, or delete and recreate rejected or disconnected Private Endpoint connections."
)
PLAYBOOK = "playbooks/cli/fix_az_net_019.sh"
logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    inventory = azure_client.get_private_link_inventory()
    if inventory is None:
        logger.warning("%s UNKNOWN: Private Endpoint inventory unavailable", RULE_ID)
        return []
    findings = []
    for item in inventory:
        status = item.get("connection_status")
        if status is None:
            logger.warning("%s UNKNOWN for %s: connection state missing", RULE_ID, item.get("endpoint_name"))
            continue
        if str(status).lower() not in {"pending", "rejected", "disconnected"}:
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
                "metadata": evidence(item, {"connection_status": status}, {"connection_status": "Approved"}),
            }
        )
    return findings
