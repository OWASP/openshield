"""AZ-IDN-015: Managed identity has a privileged subscription-scope role."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-IDN-015"
RULE_NAME = "Managed Identity Has Privileged Subscription Role"
SEVERITY = "HIGH"
CATEGORY = "Identity"
FRAMEWORKS = {"CIS": "N/A-IDN-015", "NIST": "PR.AC-4", "ISO27001": "A.8.2", "SOC2": "CC6.3"}
DESCRIPTION = (
    "A managed identity holds Owner or Contributor at subscription scope. Compromise of any resource "
    "that can use the identity would provide an unnecessarily large Azure control-plane blast radius."
)
REMEDIATION = "Replace the assignment with the narrowest role and resource scope required by the workload."
PLAYBOOK = "playbooks/cli/fix_az_idn_015.sh"

OWNER_ROLE_GUID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR_ROLE_GUID = "b24988ac-6180-42a0-ab88-20f7382dd24c"
_PRIVILEGED_ROLES = {OWNER_ROLE_GUID: "Owner", CONTRIBUTOR_ROLE_GUID: "Contributor"}

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    principals = azure_client.get_managed_identity_service_principals()
    assignments = azure_client.get_subscription_role_assignments()
    if principals is None or assignments is None:
        logger.warning("%s: managed-identity or RBAC inventory is unavailable", RULE_ID)
        return findings

    principal_names = {str(item.get("id")): str(item.get("displayName") or item.get("id")) for item in principals}
    subscription_scope = f"/subscriptions/{subscription_id}".lower()
    for assignment in assignments:
        principal_id = str(getattr(assignment, "principal_id", "") or "")
        if principal_id not in principal_names:
            continue
        scope = str(getattr(assignment, "scope", "") or "")
        if scope.rstrip("/").lower() != subscription_scope:
            continue
        role_definition_id = str(getattr(assignment, "role_definition_id", "") or "")
        role_guid = role_definition_id.rstrip("/").split("/")[-1].lower()
        role_name = _PRIVILEGED_ROLES.get(role_guid)
        if not role_name:
            continue
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": str(getattr(assignment, "id", "") or ""),
                "resource_name": principal_names[principal_id],
                "resource_type": "Microsoft.Authorization/roleAssignments",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {"principal_id": principal_id, "role": role_name, "scope": scope},
            }
        )
    return findings
