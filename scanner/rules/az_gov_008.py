"""AZ-GOV-008: Undocumented Resource Provider Registered."""

from typing import Any, Dict, List

from scanner.rules._governance_common import evaluate

RULE_ID = "AZ-GOV-008"
RULE_NAME = "Undocumented Resource Provider Registered"
SEVERITY = "MEDIUM"
CATEGORY = "Governance"
FRAMEWORKS = {"CIS": "N/A-GOV-008", "NIST": "PR.IP-1", "ISO27001": "A.5.9", "SOC2": "CC6.6"}
DESCRIPTION = "A resource provider is registered without an approved operational requirement."
REMEDIATION = (
    "Confirm the business requirement, record approval, or unregister the unused provider after impact review."
)
PLAYBOOK = "playbooks/cli/fix_az_gov_008.sh"
PERMISSIONS = "Microsoft.Resources/subscriptions/providers/read"

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
    """Evaluate AZ-GOV-008 from read-only governance evidence."""
    return evaluate(_SPEC, azure_client, subscription_id)
