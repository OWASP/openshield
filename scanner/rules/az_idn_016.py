"""AZ-IDN-016: Privileged user has no phishing-resistant MFA method registered."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-IDN-016"
RULE_NAME = "Privileged User Missing Phishing-Resistant MFA"
SEVERITY = "CRITICAL"
CATEGORY = "Identity"
FRAMEWORKS = {
    "CIS": "N/A-IDN-016",
    "NIST": "PR.AC-7",
    "ISO27001": "A.9.4.2",
    "SOC2": "CC6.1",
}
DESCRIPTION = (
    "A user assigned to a privileged directory role has no phishing-resistant "
    "authentication method registered. Phishing-resistant methods (FIDO2 security "
    "keys, Windows Hello for Business, certificate-based authentication) cannot be "
    "intercepted by adversary-in-the-middle attacks, unlike TOTP or SMS-based MFA. "
    "Privileged accounts are the highest-value targets in a tenant and must use the "
    "strongest available authentication."
)
REMEDIATION = (
    "Register a FIDO2 security key, configure Windows Hello for Business, or enrol "
    "a certificate-based authentication method for every privileged user. In Entra ID: "
    "Security > Authentication methods > Policies > enable FIDO2 or Certificate-based "
    "authentication. Then create a Conditional Access policy requiring "
    "'Phishing-resistant MFA strength' for administrator roles."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_016.sh"

_PHISHING_RESISTANT = {
    "fido2",
    "windowshelloforbusiness",
    "x509certificate",
    "microsoftauthenticatorpasswordless",
}

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    users = azure_client.get_privileged_users_mfa_methods()
    if users is None:
        logger.warning("%s: privileged MFA method inventory unavailable", RULE_ID)
        return findings

    for user in users:
        user_id = user.get("userId", "")
        if not user_id:
            continue
        methods = [m.lower() for m in (user.get("authMethodTypes") or [])]
        if any(pr in m for pr in _PHISHING_RESISTANT for m in methods):
            continue
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": f"/users/{user_id}",
                "resource_name": user.get("userDisplayName", user_id),
                "resource_type": "Microsoft.Graph/users",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "user_principal_name": user.get("userPrincipalName", ""),
                    "registered_methods": user.get("authMethodTypes") or [],
                },
            }
        )
    return findings
