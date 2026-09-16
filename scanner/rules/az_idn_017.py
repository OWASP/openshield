"""AZ-IDN-017: Global Administrator role has permanent direct assignments outside PIM."""

import logging
from typing import Any, Dict, List, Set

RULE_ID = "AZ-IDN-017"
RULE_NAME = "Global Administrator Permanently Assigned Outside PIM"
SEVERITY = "HIGH"
CATEGORY = "Identity"
FRAMEWORKS = {
    "CIS": "N/A-IDN-017",
    "NIST": "PR.AC-4",
    "ISO27001": "A.9.2.3",
    "SOC2": "CC6.3",
}
DESCRIPTION = (
    "A user holds the Global Administrator role as a permanent direct assignment "
    "rather than through a time-bound Privileged Identity Management eligible "
    "assignment. Permanent role assignments keep the full attack surface active "
    "at all times. An account compromise immediately grants unrestricted tenant "
    "control with no approval gate or time limit."
)
REMEDIATION = (
    "Remove the permanent Global Administrator assignment and replace it with a "
    "PIM-eligible assignment. In Entra ID: Identity Governance > Privileged Identity "
    "Management > Azure AD roles > Global Administrator > Assignments > Add eligible "
    "assignment. Set maximum activation duration and require approval and MFA for "
    "activation."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_017.sh"

GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    members = azure_client.get_privileged_role_members()
    pim = azure_client.get_pim_role_assignments()
    if members is None:
        logger.warning("%s: privileged role member inventory unavailable", RULE_ID)
        return findings
    if pim is None:
        logger.warning("%s: PIM assignment inventory unavailable; result is UNKNOWN", RULE_ID)
        return findings

    pim_eligible_principals: Set[str] = set()
    for a in pim:
        if a.get("roleId", "").lower() == GLOBAL_ADMIN_ROLE_ID and a.get("assignmentType") == "Eligible":
            pim_eligible_principals.add(a.get("principalId", ""))

    for member in members:
        if member.get("roleId", "").lower() != GLOBAL_ADMIN_ROLE_ID:
            continue
        principal_id = member.get("userId", "")
        if not principal_id:
            continue
        if principal_id in pim_eligible_principals:
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
                    "role_name": member.get("roleName", "Global Administrator"),
                    "pim_coverage": False,
                },
            }
        )
    return findings
