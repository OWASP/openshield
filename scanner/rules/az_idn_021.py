"""AZ-IDN-021: No Conditional Access policy blocks legacy authentication protocols."""

from typing import Any, Dict, List

RULE_ID = "AZ-IDN-021"
RULE_NAME = "Legacy Authentication Not Blocked by Conditional Access"
SEVERITY = "HIGH"
CATEGORY = "Identity"
FRAMEWORKS = {
    "CIS": "N/A-IDN-021",
    "NIST": "PR.AC-7",
    "ISO27001": "A.9.4.2",
    "SOC2": "CC6.1",
}
DESCRIPTION = (
    "No enabled Conditional Access policy blocks legacy authentication protocols "
    "such as Basic authentication, Exchange ActiveSync, and other clients that do "
    "not support modern authentication. Legacy protocols cannot enforce MFA, making "
    "them a direct bypass for any MFA-based Conditional Access policy. The majority "
    "of password-spray attacks targeting Microsoft 365 use legacy authentication."
)
REMEDIATION = (
    "Create a Conditional Access policy that blocks all legacy authentication. "
    "In Entra ID: Security > Conditional Access > New policy. Set Users to include "
    "all users, set Conditions > Client apps > select Exchange ActiveSync clients "
    "and Other clients, set Grant to Block access, and enable the policy. "
    "Run in Report-only mode first to identify affected users and clients."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_021.sh"

_LEGACY_CLIENT_TYPES = {"exchangeActiveSync", "other"}


def _covers_all_users(policy: Dict[str, Any]) -> bool:
    conditions = policy.get("conditions") or {}
    users = conditions.get("users") or {}
    include_users = users.get("includeUsers") or []
    return "All" in include_users


def _blocks_legacy_auth(policy: Dict[str, Any]) -> bool:
    if policy.get("state") != "enabled":
        return False
    if not _covers_all_users(policy):
        return False
    grant = policy.get("grantControls") or {}
    built_in = grant.get("builtInControls") or []
    if "block" not in built_in:
        return False
    conditions = policy.get("conditions") or {}
    client_apps = conditions.get("clientAppTypes") or []
    if "all" in [c.lower() for c in client_apps]:
        return True
    return bool(_LEGACY_CLIENT_TYPES.intersection(set(client_apps)))


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    policies = azure_client.get_conditional_access_policies()
    if any(_blocks_legacy_auth(p) for p in (policies or [])):
        return []
    reason = (
        "No Conditional Access policies found — Graph API may be inaccessible."
        if not policies
        else "No enabled policy blocks legacy authentication client types."
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
