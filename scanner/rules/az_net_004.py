"""AZ-NET-004: NSG with no rules configured (empty ruleset)."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-NET-004"
RULE_NAME = "NSG with no rules configured"
SEVERITY = "MEDIUM"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "9.2", "NIST": "SC-7", "ISO27001": "A.8.20"}
DESCRIPTION = (
    "A Network Security Group exists but has no custom security rules configured. "
    "An empty NSG relies entirely on Azure default rules which may not meet your "
    "security requirements and provides no meaningful access control."
)
REMEDIATION = (
    "Add explicit inbound and outbound rules to the NSG that reflect the "
    "principle of least privilege. Deny all traffic by default and only allow "
    "what is required for the workload."
)
PLAYBOOK = "playbooks/cli/fix_az_net_004.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect NSGs with no custom security rules."""
    findings: List[Dict[str, Any]] = []

    for nsg in azure_client.get_network_security_groups():
        rules = getattr(nsg, "security_rules", []) or []
        if len(rules) == 0:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": getattr(nsg, "id", ""),
                    "resource_name": getattr(nsg, "name", ""),
                    "resource_type": "Microsoft.Network/networkSecurityGroups",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "rule_count": len(rules),
                    },
                }
            )

    return findings
