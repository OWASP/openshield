"""AZ-IDN-002: No MFA enforced on admin accounts via Conditional Access."""

from typing import Any, Dict, List

RULE_ID = "AZ-IDN-002"
RULE_NAME = "No MFA Enforced on Admin Accounts via Conditional Access"
SEVERITY = "HIGH"
CATEGORY = "Identity"
FRAMEWORKS = {"CIS": "1.2.4", "NIST": "PR.AC-1", "ISO27001": "A.8.5"}
DESCRIPTION = (
    "No Conditional Access policy is enabled that requires multi-factor authentication "
    "for administrator accounts. Without MFA enforcement, a single compromised password "
    "is sufficient for an attacker to gain privileged access to the Azure tenant."
)
REMEDIATION = (
    "Create a Conditional Access policy that targets administrator directory roles "
    "(Global Administrator, Privileged Role Administrator, etc.) and requires "
    "MFA as a grant control. Ensure the policy state is set to 'enabled'."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_002.sh"

# Privileged Azure AD directory role IDs (subset most relevant for MFA enforcement)
ADMIN_ROLE_IDS = {
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
}


def _policy_enforces_mfa_for_admins(policy: Dict[str, Any]) -> bool:
    """Return True if the CA policy is enabled, requires MFA, and targets admins."""
    if policy.get("state") != "enabled":
        return False

    grant = policy.get("grantControls") or {}
    controls = grant.get("builtInControls", [])
    if "mfa" not in controls:
        return False

    conditions = policy.get("conditions") or {}
    users = conditions.get("users") or {}

    # Covers all users → definitely covers admins
    if "All" in (users.get("includeUsers") or []):
        return True

    # Covers specific admin roles
    included_roles = set(users.get("includeRoles") or [])
    return bool(included_roles & ADMIN_ROLE_IDS)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect tenants where no CA policy enforces MFA for administrators.

    Requires the credential to have the 'Policy.Read.All' Microsoft Graph
    permission. If the Graph call fails (e.g. insufficient permissions), a
    finding is still raised because the posture cannot be verified.
    """
    policies = azure_client.get_conditional_access_policies()

    if policies and any(_policy_enforces_mfa_for_admins(p) for p in policies):
        return []

    reason = (
        "No Conditional Access policies found — Graph API may be inaccessible."
        if not policies
        else "Existing Conditional Access policies do not enforce MFA for admin roles."
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
            "metadata": {"reason": reason, "policies_found": len(policies)},
        }
    ]
