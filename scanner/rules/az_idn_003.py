"""AZ-IDN-003: Guest user invitations not restricted to admins in Entra ID."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-IDN-003"
RULE_NAME = "Guest user invitations not restricted to admins in Entra ID"
SEVERITY = "MEDIUM"
CATEGORY = "Identity"
FRAMEWORKS = {"CIS": "1.15", "NIST": "PR.AC-1", "ISO27001": "A.5.16"}
DESCRIPTION = (
    "Guest user invitations in Entra ID are not restricted to administrators. "
    "Any organisation member can invite external users into the tenant without "
    "centralised review or approval. This bypasses formal external identity "
    "provisioning controls and increases the risk of unauthorised access by "
    "untrusted parties."
)
REMEDIATION = (
    "Restrict guest invitations to admins only by setting the "
    "'allowInvitesFrom' policy to 'adminsAndGuestInviters' or 'admins' "
    "in Entra ID. Navigate to: Entra ID > External Identities > "
    "External collaboration settings > Guest invite settings. "
    "Set to 'Only users assigned to specific admin roles can invite guest users'."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_003.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect unrestricted guest user invitation settings in Entra ID."""
    findings: List[Dict[str, Any]] = []

    try:
        import requests

        token = azure_client.credential.get_token("https://graph.microsoft.com/.default")
        headers = {"Authorization": f"Bearer {token.token}"}

        response = requests.get(
            "https://graph.microsoft.com/v1.0/policies/authorizationPolicy",
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()
        policy = response.json()

    except Exception as exc:
        logger.error("AZ-IDN-003: Failed to fetch authorization policy from Graph API: %s", exc)
        logger.warning("AZ-IDN-003: Ensure the service principal has Directory.Read.All permission on Microsoft Graph.")
        return findings

    allow_invites_from = policy.get("allowInvitesFrom", "everyone")

    restricted_values = {"admins", "adminsAndGuestInviters"}
    if allow_invites_from not in restricted_values:
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": f"/tenants/{policy.get('id', 'unknown')}/policies/authorizationPolicy",
                "resource_name": "authorizationPolicy",
                "resource_type": "Microsoft.Graph/authorizationPolicy",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "allow_invites_from": allow_invites_from,
                    "policy_id": policy.get("id", ""),
                    "display_name": policy.get("displayName", ""),
                },
            }
        )

    return findings
