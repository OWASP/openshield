"""AZ-IDN-025: Role-assignable privileged group has no owner configured."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-IDN-025"
RULE_NAME = "Privileged Role-Assignable Group Has No Owner"
SEVERITY = "MEDIUM"
CATEGORY = "Identity"
FRAMEWORKS = {
    "CIS": "N/A-IDN-025",
    "NIST": "PR.AC-4",
    "ISO27001": "A.9.2.5",
    "SOC2": "CC6.3",
}
DESCRIPTION = (
    "An Entra ID group configured with 'isAssignableToRole=true' has no owner. "
    "Role-assignable groups can be used to grant directory role membership to every "
    "member of the group simultaneously. Without an owner, membership changes are "
    "uncontrolled: any administrator who can modify group membership can indirectly "
    "escalate privileges to the associated role. Ownerless privileged groups also "
    "prevent access reviews from functioning correctly."
)
REMEDIATION = (
    "Assign at least one owner to every role-assignable group. In Entra ID: "
    "Groups > select the group > Owners > Add owners. The owner should be a "
    "named individual (not a service account) who is responsible for approving "
    "membership changes. Configure access reviews for the group: Identity Governance "
    "> Access Reviews > New access review > select the group."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_025.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    groups = azure_client.get_privileged_groups()
    if groups is None:
        logger.warning("%s: privileged group inventory unavailable", RULE_ID)
        return findings

    for group in groups:
        group_id = group.get("id", "")
        if not group_id:
            continue
        if group.get("ownerCount", 0) > 0:
            continue
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": f"/groups/{group_id}",
                "resource_name": group.get("displayName", group_id),
                "resource_type": "Microsoft.Graph/groups",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {"owner_count": 0},
            }
        )
    return findings
