"""AZ-GOV-010: Security Configuration Drift Exceeds SLA."""

from typing import Any, Dict, List

from scanner.evaluation import RuleEvaluation, fail_findings
from scanner.rules._governance_common import evaluate as _evaluate

RULE_ID = "AZ-GOV-010"
RULE_NAME = "Security Configuration Drift Exceeds SLA"
SEVERITY = "HIGH"
CATEGORY = "Governance"
FRAMEWORKS = {"CIS": "N/A-GOV-010", "NIST": "DE.CM-8", "ISO27001": "A.8.8", "SOC2": "CC7.2"}
DESCRIPTION = "Confirmed non-compliant policy state has remained unresolved beyond the approved remediation SLA."
REMEDIATION = "Investigate the policy state, remediate the drift, and confirm compliance with a new evaluation."
PLAYBOOK = "playbooks/cli/fix_az_gov_010.sh"
PERMISSIONS = "Microsoft.PolicyInsights/policyStates/queryResults/action"

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
    """Report AZ-GOV-010 coverage: a status for every resource it looked at, PASS included."""
    return _evaluate(_SPEC, azure_client, subscription_id)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect AZ-GOV-010 violations as findings (thin wrapper over evaluate())."""
    return fail_findings(evaluate(azure_client, subscription_id))
