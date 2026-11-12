"""AZ-GOV-007: Privileged Access Assigned at Broad Scope."""

from typing import Any, Dict, List

from scanner.evaluation import RuleEvaluation, fail_findings
from scanner.rules._governance_common import evaluate as _evaluate

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


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report AZ-GOV-007 coverage: a status for every resource it looked at, PASS included."""
    return _evaluate(_SPEC, azure_client, subscription_id)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect AZ-GOV-007 violations as findings (thin wrapper over evaluate())."""
    return fail_findings(evaluate(azure_client, subscription_id))
