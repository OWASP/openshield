"""AZ-IDN-007: Active users in Entra ID with no MFA methods registered."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-IDN-007"
RULE_NAME = "Active User with No MFA Registered in Entra ID"
SEVERITY = "HIGH"
CATEGORY = "Identity"
FRAMEWORKS = {"CIS": "1.1", "NIST": "PR.AC-7", "ISO27001": "A.8.5", "SOC2": "CC6.1"}
DESCRIPTION = (
    "One or more active user accounts in Entra ID have no multi-factor "
    "authentication methods registered. Accounts without MFA are vulnerable to "
    "password spray, credential stuffing, and phishing attacks. A single "
    "compromised password gives an attacker full account access with no additional "
    "verification required."
)
REMEDIATION = (
    "Enforce MFA registration for all users via a Conditional Access policy. "
    "Navigate to: Entra ID > Protection > Conditional Access > Policies > New policy. "
    "Set Users to include all users, grant access requiring multi-factor "
    "authentication, and enable the policy. Users without MFA registered will be "
    "prompted on next sign-in. Use the Authentication methods registration campaign "
    "to drive adoption before the policy enforcement date."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_007.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect active user accounts with no MFA methods registered."""
    findings: List[Dict[str, Any]] = []

    try:
        import requests

        token = azure_client.credential.get_token("https://graph.microsoft.com/.default")
        headers = {"Authorization": f"Bearer {token.token}"}

        next_url = "https://graph.microsoft.com/v1.0/reports/credentialUserRegistrationDetails?$top=999"
        registrations = []
        while next_url:
            response = requests.get(next_url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            registrations.extend(data.get("value", []))
            next_url = data.get("@odata.nextLink")

    except Exception as exc:
        logger.error(
            "AZ-IDN-007: Failed to fetch MFA registration report from Graph API: %s",
            exc,
        )
        logger.warning("AZ-IDN-007: Ensure the service principal has Reports.Read.All permission on Microsoft Graph.")
        return findings

    for reg in registrations:
        if not reg.get("isEnabled", True):
            continue
        if reg.get("isMfaRegistered", True):
            continue

        user_id = reg.get("id", "")
        user_principal_name = reg.get("userPrincipalName", "")
        user_display_name = reg.get("userDisplayName", user_principal_name)

        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": f"/users/{user_id}",
                "resource_name": user_display_name,
                "resource_type": "Microsoft.Graph/users",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "user_id": user_id,
                    "user_principal_name": user_principal_name,
                    "is_mfa_registered": False,
                    "is_mfa_capable": reg.get("isMfaCapable", False),
                    "is_sspr_registered": reg.get("isSsprRegistered", False),
                },
            }
        )

    return findings
