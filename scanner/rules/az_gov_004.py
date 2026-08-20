"""AZ-GOV-004: Policy Exemption Missing Governance Metadata."""

from typing import Any, Dict, List

from scanner.rules._governance_common import evaluate

RULE_ID = "AZ-GOV-004"
RULE_NAME = "Policy Exemption Missing Governance Metadata"
SEVERITY = "MEDIUM"
CATEGORY = "Governance"
FRAMEWORKS = {"CIS": "N/A-GOV-004", "NIST": "PR.IP-1", "ISO27001": "A.5.1", "SOC2": "CC5.3"}
DESCRIPTION = "A policy exemption lacks an accountable owner, justification, or valid expiration date."
REMEDIATION = "Add the required exemption metadata or remove the exemption if it is no longer approved."
PLAYBOOK = "playbooks/cli/fix_az_gov_004.sh"
PERMISSIONS = "Microsoft.Authorization/policyExemptions/read"

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
    """Evaluate AZ-GOV-004 from read-only governance evidence."""
    return evaluate(_SPEC, azure_client, subscription_id)
