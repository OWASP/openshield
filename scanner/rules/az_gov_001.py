"""AZ-GOV-001: Subscription Outside Approved Management Group Hierarchy."""

from typing import Any, Dict, List

from scanner.rules._governance_common import evaluate

RULE_ID = "AZ-GOV-001"
RULE_NAME = "Subscription Outside Approved Management Group Hierarchy"
SEVERITY = "HIGH"
CATEGORY = "Governance"
FRAMEWORKS = {"CIS": "N/A-GOV-001", "NIST": "PR.AC-4", "ISO27001": "A.5.15", "SOC2": "CC6.3"}
DESCRIPTION = "An Azure subscription is outside the organisation's approved management-group hierarchy."
REMEDIATION = (
    "Move the subscription into an approved management group after validating inherited policy and access effects."
)
PLAYBOOK = "playbooks/cli/fix_az_gov_001.sh"
PERMISSIONS = "Microsoft.Management/managementGroups/read"

_SPEC = {
    "id": RULE_ID,
    "name": RULE_NAME,
    "severity": SEVERITY,
    "description": DESCRIPTION,
    "remediation": REMEDIATION,
    "playbook": PLAYBOOK,
    "frameworks": FRAMEWORKS,
    "permissions": PERMISSIONS,
}


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Evaluate AZ-GOV-001 from read-only governance evidence."""
    return evaluate(_SPEC, azure_client, subscription_id)
