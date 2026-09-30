"""AZ-GOV-006: Excessive Subscription Owner Assignments."""

from typing import Any, Dict, List

from scanner.rules._governance_common import evaluate

RULE_ID = "AZ-GOV-006"
RULE_NAME = "Excessive Subscription Owner Assignments"
SEVERITY = "HIGH"
CATEGORY = "Governance"
FRAMEWORKS = {"CIS": "N/A-GOV-006", "NIST": "PR.AC-4", "ISO27001": "A.5.18", "SOC2": "CC6.3"}
DESCRIPTION = "The subscription has more Owner role assignments than the organisation permits."
REMEDIATION = (
    "Remove unnecessary Owner assignments and use least-privilege roles with eligible activation where appropriate."
)
PLAYBOOK = "playbooks/cli/fix_az_gov_006.sh"
PERMISSIONS = "Microsoft.Authorization/roleAssignments/read"

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
    """Evaluate AZ-GOV-006 from read-only governance evidence."""
    return evaluate(_SPEC, azure_client, subscription_id)
