"""AZ-GOV-003: Preventive Policy Uses Non-Enforcing Effect."""

from typing import Any, Dict, List

from scanner.rules._governance_common import evaluate

RULE_ID = "AZ-GOV-003"
RULE_NAME = "Preventive Policy Uses Non-Enforcing Effect"
SEVERITY = "HIGH"
CATEGORY = "Governance"
FRAMEWORKS = {"CIS": "N/A-GOV-003", "NIST": "PR.IP-1", "ISO27001": "A.5.1", "SOC2": "CC5.2"}
DESCRIPTION = "A mandatory preventive policy assignment uses an effect that does not enforce the approved control."
REMEDIATION = "Update the assignment effect to an organisation-approved preventive effect after testing impact."
PLAYBOOK = "playbooks/cli/fix_az_gov_003.sh"
PERMISSIONS = "Microsoft.Authorization/policyAssignments/read"

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
    """Evaluate AZ-GOV-003 from read-only governance evidence."""
    return evaluate(_SPEC, azure_client, subscription_id)
