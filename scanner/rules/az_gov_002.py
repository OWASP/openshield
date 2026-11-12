"""AZ-GOV-002: Required Security Policy Initiative Missing."""

from typing import Any, Dict, List

from scanner.evaluation import RuleEvaluation, fail_findings
from scanner.rules._governance_common import evaluate as _evaluate

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


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report AZ-GOV-002 coverage: a status for every resource it looked at, PASS included."""
    return _evaluate(_SPEC, azure_client, subscription_id)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect AZ-GOV-002 violations as findings (thin wrapper over evaluate())."""
    return fail_findings(evaluate(azure_client, subscription_id))
