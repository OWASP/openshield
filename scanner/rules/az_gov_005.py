"""AZ-GOV-005: Critical Production Resource Missing Deletion Lock."""

from typing import Any, Dict, List

from scanner.evaluation import RuleEvaluation, fail_findings
from scanner.rules._governance_common import evaluate as _evaluate

RULE_ID = "AZ-GOV-005"
RULE_NAME = "Critical Production Resource Missing Deletion Lock"
SEVERITY = "HIGH"
CATEGORY = "Governance"
FRAMEWORKS = {"CIS": "N/A-GOV-005", "NIST": "PR.IP-3", "ISO27001": "A.8.9", "SOC2": "CC6.5"}
DESCRIPTION = "A production resource in the protected scope has no effective deletion lock."
REMEDIATION = "Apply a CanNotDelete lock at the resource or an approved parent scope after validating operations."
PLAYBOOK = "playbooks/cli/fix_az_gov_005.sh"
PERMISSIONS = "Microsoft.Authorization/locks/read"

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
    """Report AZ-GOV-005 coverage: a status for every resource it looked at, PASS included."""
    return _evaluate(_SPEC, azure_client, subscription_id)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect AZ-GOV-005 violations as findings (thin wrapper over evaluate())."""
    return fail_findings(evaluate(azure_client, subscription_id))
