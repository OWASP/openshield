"""AZ-NET-006: Public IP address unassociated with any resource."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-NET-006"
RULE_NAME = "Public IP address unassociated with any resource"
SEVERITY = "LOW"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "9.1", "NIST": "CM-7", "ISO27001": "A.8.20"}
DESCRIPTION = (
    "A public IP address exists in the subscription but is not associated "
    "with any resource such as a VM, load balancer or application gateway. "
    "Unassociated public IPs represent unnecessary cost and attack surface "
    "and may indicate leftover resources from decommissioned workloads."
)
REMEDIATION = (
    "Delete the unassociated public IP address if it is no longer needed. "
    "If it is reserved for future use, document the reason and tag it "
    "appropriately so it can be tracked and reviewed regularly."
)
PLAYBOOK = "playbooks/cli/fix_az_net_006.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect public IP addresses not associated with any resource."""
    findings: List[Dict[str, Any]] = []

    for pip in azure_client.get_public_ip_addresses():
        ip_config = getattr(pip, "ip_configuration", None)
        nat_gateway = getattr(pip, "nat_gateway", None)
        if not ip_config and not nat_gateway:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": getattr(pip, "id", ""),
                    "resource_name": getattr(pip, "name", ""),
                    "resource_type": "Microsoft.Network/publicIPAddresses",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "ip_address": getattr(pip, "ip_address", ""),
                        "location": getattr(pip, "location", ""),
                        "sku": getattr(getattr(pip, "sku", None), "name", ""),
                    },
                }
            )

    return findings
