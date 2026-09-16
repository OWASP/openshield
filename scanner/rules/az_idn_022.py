"""AZ-IDN-022: No Conditional Access policy protects Azure management operations."""

from typing import Any, Dict, List

RULE_ID = "AZ-IDN-022"
RULE_NAME = "Azure Management Not Protected by Conditional Access"
SEVERITY = "HIGH"
CATEGORY = "Identity"
FRAMEWORKS = {
    "CIS": "N/A-IDN-022",
    "NIST": "PR.AC-4",
    "ISO27001": "A.9.4.1",
    "SOC2": "CC6.6",
}
DESCRIPTION = (
    "No enabled Conditional Access policy requires MFA or other controls when "
    "accessing Azure management interfaces (Azure portal, Azure CLI, Azure PowerShell, "
    "ARM API). Without this control, any authenticated user — including compromised "
    "accounts — can access Azure management without additional verification, enabling "
    "resource modification, data exfiltration, and privilege escalation."
)
REMEDIATION = (
    "Create a Conditional Access policy targeting the Microsoft Azure Management "
    "cloud app. In Entra ID: Security > Conditional Access > New policy. Set Users "
    "to include all users, set Cloud apps to 'Microsoft Azure Management' "
    "(app ID: 797f4846-ba00-4fd7-ba43-dac1f8f63013), set Grant to require MFA, "
    "and enable the policy. Test in Report-only mode first."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_022.sh"

# Well-known app ID for Microsoft Azure Management (portal, CLI, PS, ARM)
_AZURE_MGMT_APP_ID = "797f4846-ba00-4fd7-ba43-dac1f8f63013"


def _covers_all_users(policy: Dict[str, Any]) -> bool:
    conditions = policy.get("conditions") or {}
    users = conditions.get("users") or {}
    include_users = users.get("includeUsers") or []
    return "All" in include_users


def _protects_azure_management(policy: Dict[str, Any]) -> bool:
    if policy.get("state") != "enabled":
        return False
    if not _covers_all_users(policy):
        return False
    grant = policy.get("grantControls") or {}
    built_in = grant.get("builtInControls") or []
    if "mfa" not in built_in and "block" not in built_in:
        return False
    conditions = policy.get("conditions") or {}
    apps = conditions.get("applications") or {}
    include_apps = apps.get("includeApplications") or []
    return "All" in include_apps or _AZURE_MGMT_APP_ID in include_apps


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    policies = azure_client.get_conditional_access_policies()
    if any(_protects_azure_management(p) for p in (policies or [])):
        return []
    reason = (
        "No Conditional Access policies found — Graph API may be inaccessible."
        if not policies
        else "No enabled policy requires MFA or block for Azure management access."
    )
    return [
        {
            "rule_id": RULE_ID,
            "rule_name": RULE_NAME,
            "severity": SEVERITY,
            "category": CATEGORY,
            "resource_id": f"/tenants/{subscription_id}/conditionalAccess",
            "resource_name": "Conditional Access Policies",
            "resource_type": "Microsoft.AzureActiveDirectory/conditionalAccessPolicies",
            "description": DESCRIPTION,
            "remediation": REMEDIATION,
            "playbook": PLAYBOOK,
            "frameworks": FRAMEWORKS,
            "metadata": {"reason": reason, "policies_found": len(policies or [])},
        }
    ]
