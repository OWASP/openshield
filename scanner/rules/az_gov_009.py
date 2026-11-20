"""AZ-GOV-009: Production Resource Missing Ownership Metadata."""

from typing import Any, Dict, List

from scanner.evaluation import RuleEvaluation, fail_findings
from scanner.rules._governance_common import evaluate as _evaluate

RULE_ID = "AZ-GOV-009"
RULE_NAME = "Production Resource Missing Ownership Metadata"
SEVERITY = "MEDIUM"
CATEGORY = "Governance"
FRAMEWORKS = {"CIS": "N/A-GOV-009", "NIST": "ID.AM-1", "ISO27001": "A.5.9", "SOC2": "CC2.2"}
DESCRIPTION = "A production resource has no recognised accountable ownership tag."
REMEDIATION = "Add an approved ownership tag with a current team or service owner."
PLAYBOOK = "playbooks/cli/fix_az_gov_009.sh"
PERMISSIONS = "Microsoft.Resources/subscriptions/resources/read"

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
    """Report AZ-GOV-009 coverage: a status for every resource it looked at, PASS included."""
    return _evaluate(_SPEC, azure_client, subscription_id)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect AZ-GOV-009 violations as findings (thin wrapper over evaluate())."""
    return fail_findings(evaluate(azure_client, subscription_id))
