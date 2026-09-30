"""AZ-GOV-002: Required Security Policy Initiative Missing."""

from typing import Any, Dict, List

from scanner.rules._governance_common import evaluate

RULE_ID = "AZ-GOV-002"
RULE_NAME = "Required Security Policy Initiative Missing"
SEVERITY = "HIGH"
CATEGORY = "Governance"
FRAMEWORKS = {"CIS": "N/A-GOV-002", "NIST": "PR.IP-1", "ISO27001": "A.5.1", "SOC2": "CC5.2"}
DESCRIPTION = "A required security policy initiative is not assigned at its approved scope."
REMEDIATION = "Assign the required initiative at the approved scope and validate its effective state."
PLAYBOOK = "playbooks/cli/fix_az_gov_002.sh"
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
    """Evaluate AZ-GOV-002 from read-only governance evidence."""
    return evaluate(_SPEC, azure_client, subscription_id)
