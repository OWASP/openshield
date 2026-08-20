"""AZ-GOV-007: Privileged Access Assigned at Broad Scope."""

from typing import Any, Dict, List

from scanner.rules._governance_common import evaluate

RULE_ID = "AZ-GOV-007"
RULE_NAME = "Privileged Access Assigned at Broad Scope"
SEVERITY = "HIGH"
CATEGORY = "Governance"
FRAMEWORKS = {"CIS": "N/A-GOV-007", "NIST": "PR.AC-4", "ISO27001": "A.5.18", "SOC2": "CC6.3"}
DESCRIPTION = "A privileged role is assigned outside the organisation's approved scopes."
REMEDIATION = "Reduce the assignment scope and use eligible time-bound access where supported."
PLAYBOOK = "playbooks/cli/fix_az_gov_007.sh"
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
    """Evaluate AZ-GOV-007 from read-only governance evidence."""
    return evaluate(_SPEC, azure_client, subscription_id)
