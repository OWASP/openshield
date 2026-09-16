"""AZ-NET-022: Critical PaaS resource is publicly accessible."""

import logging
import os
from typing import Any, Dict, List

from scanner.rules._perimeter_common import metadata

RULE_ID = "AZ-NET-022"
RULE_NAME = "Critical PaaS Resource Is Publicly Accessible Without Approved Exception"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "N/A-NET-022", "NIST": "PR.AC-3", "ISO27001": "A.13.1.1", "SOC2": "CC6.6"}
DESCRIPTION = (
    "A critical PaaS resource permits public network access and is not in the explicit approved-exception list."
)
REMEDIATION = (
    "Validate private connectivity, disable public network access, or add a time-bound "
    "approved exception through deployment configuration."
)
PLAYBOOK = "playbooks/cli/fix_az_net_022.sh"
logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    inventories = azure_client.get_critical_paas_inventory()
    exceptions = {
        value.strip().lower()
        for value in os.getenv("OPENSHIELD_PUBLIC_PAAS_EXCEPTIONS", "").split(",")
        if value.strip()
    }
    findings = []
    for service, resources in inventories.items():
        if resources is None:
            logger.warning("%s UNKNOWN: %s inventory unavailable", RULE_ID, service)
            continue
        for item in resources:
            state = item.get("public_network_access")
            if state is None:
                logger.warning("%s UNKNOWN for %s: public access state missing", RULE_ID, item.get("resource_name"))
                continue
            if state is not True or item.get("resource_id", "").lower() in exceptions:
                continue
            evidence = metadata(
                resource_id=item.get("resource_id", ""),
                observed={"public_network_access": "Enabled", "approved_exception": False},
                expected={"public_network_access": "Disabled", "or_approved_exception": True},
                source=f"Azure Resource Manager: {item.get('resource_type', service)}",
                timestamp=item.get("collected_at", ""),
                permissions=[f"{item.get('resource_type', service)}/read"],
            )
            evidence["location"] = item.get("location", "")
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": item.get("resource_id", ""),
                    "resource_name": item.get("resource_name", ""),
                    "resource_type": item.get("resource_type", ""),
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": evidence,
                }
            )
    return findings
