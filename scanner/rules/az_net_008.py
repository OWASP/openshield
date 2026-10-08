"""AZ-NET-008: Load balancer with no backend pool configured."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-NET-008"
RULE_NAME = "Load balancer with no backend pool configured"
SEVERITY = "LOW"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "9.7", "NIST": "CM-7", "ISO27001": "A.8.20", "SOC2": "CC8.1"}
DESCRIPTION = (
    "A load balancer exists in the subscription but has no backend pool "
    "configured. A load balancer with no backend pool is either misconfigured "
    "or is a leftover resource from a decommissioned workload. It represents "
    "unnecessary cost and indicates poor resource hygiene."
)
REMEDIATION = (
    "If the load balancer is no longer needed, delete it to reduce cost and "
    "attack surface. If it is still required, configure a backend pool with "
    "the appropriate virtual machines or scale set instances."
)
PLAYBOOK = "playbooks/cli/fix_az_net_008.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect load balancers with no backend pool configured."""
    findings: List[Dict[str, Any]] = []

    for lb in azure_client.get_load_balancers():
        backend_pools = getattr(lb, "backend_address_pools", []) or []
        if len(backend_pools) == 0:
            parsed = azure_client.parse_resource_id(getattr(lb, "id", ""))
            resource_group = parsed.get("resource_group", "")
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": getattr(lb, "id", ""),
                    "resource_name": getattr(lb, "name", ""),
                    "resource_type": "Microsoft.Network/loadBalancers",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "location": getattr(lb, "location", ""),
                        "backend_pool_count": len(backend_pools),
                        "resource_group": resource_group,
                    },
                }
            )

    return findings
