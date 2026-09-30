"""AZ-GOV-010: Security Configuration Drift Exceeds SLA."""

from typing import Any, Dict, List

from scanner.rules._governance_common import evaluate

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


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Evaluate AZ-GOV-010 from read-only governance evidence."""
    return evaluate(_SPEC, azure_client, subscription_id)
