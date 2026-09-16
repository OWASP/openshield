"""AZ-IDN-018: Privileged role assigned directly without Privileged Identity Management."""

import logging
from typing import Any, Dict, List, Set, Tuple

RULE_ID = "AZ-IDN-018"
RULE_NAME = "Privileged Role Assigned Outside Privileged Identity Management"
SEVERITY = "HIGH"
CATEGORY = "Identity"
FRAMEWORKS = {
    "CIS": "N/A-IDN-018",
    "NIST": "PR.AC-4",
    "ISO27001": "A.9.2.3",
    "SOC2": "CC6.3",
}
DESCRIPTION = (
    "A user holds a privileged directory role through a permanent direct assignment "
    "rather than through Privileged Identity Management. Without PIM, privileged access "
    "is always-on with no activation approval, no time limit, no MFA step-up, and no "
    "audit trail for when the privilege was actually used. Any account compromise "
    "instantly delivers standing administrative access."
)
REMEDIATION = (
    "Migrate all privileged role assignments to PIM eligible assignments. In Entra ID: "
    "Identity Governance > Privileged Identity Management > Azure AD roles > select the "
    "role > Assignments > Add eligible assignment. Remove the corresponding permanent "
    "active assignment after the eligible assignment is confirmed. Set activation "
    "settings to require MFA and justification."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_018.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    members = azure_client.get_privileged_role_members()
    pim = azure_client.get_pim_role_assignments()
    if members is None:
        logger.warning("%s: privileged role member inventory unavailable", RULE_ID)
        return findings

    pim_covered: Set[Tuple[str, str]] = set()
    if pim is not None:
        for a in pim:
            if a.get("assignmentType") == "Eligible":
                pim_covered.add((a.get("principalId", ""), a.get("roleId", "").lower()))

    for member in members:
        principal_id = member.get("userId", "")
        role_id = member.get("roleId", "").lower()
        if not principal_id or not role_id:
            continue
        if (principal_id, role_id) in pim_covered:
            continue
        principal_type = member.get("principalType", "user")
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": f"/{principal_type}/{principal_id}",
                "resource_name": member.get("userDisplayName", principal_id),
                "resource_type": "Microsoft.Graph/users",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "principal_name": member.get("userPrincipalName", ""),
                    "displayName": member.get("userDisplayName", ""),
                    "role_name": member.get("roleName", ""),
                    "role_id": role_id,
                },
            }
        )
    return findings
