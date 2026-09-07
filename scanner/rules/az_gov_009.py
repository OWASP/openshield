"""AZ-GOV-009: Production Resource Missing Ownership Metadata."""

from typing import Any, Dict, List

from scanner.rules._governance_common import evaluate

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


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Evaluate AZ-GOV-009 from read-only governance evidence."""
    return evaluate(_SPEC, azure_client, subscription_id)
