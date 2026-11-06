"""AZ-GOV-001: Subscription Outside Approved Management Group Hierarchy."""

from typing import Any, Dict, List

from scanner.evaluation import RuleEvaluation, fail_findings
from scanner.rules._governance_common import evaluate as _evaluate

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


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report AZ-GOV-001 coverage: a status for every resource it looked at, PASS included."""
    return _evaluate(_SPEC, azure_client, subscription_id)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect AZ-GOV-001 violations as findings (thin wrapper over evaluate())."""
    return fail_findings(evaluate(azure_client, subscription_id))
