"""AZ-GOV-005: Critical Production Resource Missing Deletion Lock."""

from typing import Any, Dict, List

from scanner.rules._governance_common import evaluate

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


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Evaluate AZ-GOV-005 from read-only governance evidence."""
    return evaluate(_SPEC, azure_client, subscription_id)
