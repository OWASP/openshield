"""AZ-IDN-004: No Privileged Identity Management for admin roles."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-IDN-004"
RULE_NAME = "No Privileged Identity Management for Admin Roles"
SEVERITY = "HIGH"
CATEGORY = "Identity"
FRAMEWORKS = {"CIS": "1.16", "NIST": "PR.AC-4", "ISO27001": "A.8.2", "SOC2": "CC6.3"}
DESCRIPTION = (
    "Privileged Identity Management (PIM) is not configured for one or more admin roles "
    "in Entra ID. Without PIM, admin roles are permanently assigned with no just-in-time "
    "access controls, approval workflows, or time-bound activation. Any compromised admin "
    "account has constant unrestricted access with no time limit."
)
REMEDIATION = (
    "Enable Privileged Identity Management for all admin roles in Entra ID. "
    "Navigate to: Entra ID > Identity Governance > Privileged Identity Management > "
    "Azure AD roles > Settings. Configure eligible assignments with time-bound "
    "activation, MFA on activation, and approval workflows for all privileged roles."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_004.sh"

logger = logging.getLogger(__name__)

PRIVILEGED_ROLE_NAMES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Conditional Access Administrator",
    "Helpdesk Administrator",
    "User Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
}


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect admin roles without PIM eligible assignments configured."""
    findings: List[Dict[str, Any]] = []

    try:
        import requests

        # Fetch token once and reuse headers for both API calls
        token = azure_client.credential.get_token("https://graph.microsoft.com/.default")
        headers = {"Authorization": f"Bearer {token.token}"}

        # Step 1 — Get all role definitions
        response = requests.get(
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions",
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()
        role_definitions = response.json().get("value", [])

        # Step 2 — Get all PIM eligible role assignments
        response = requests.get(
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules",
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()
        eligible_schedules = response.json().get("value", [])

    except Exception as exc:
        logger.error("AZ-IDN-004: Failed to fetch data from Graph API: %s", exc)
        logger.warning(
            "AZ-IDN-004: Ensure the service principal has RoleManagement.Read.Directory permission on Microsoft Graph."
        )
        return findings

    # Build set of role definition IDs that have PIM eligible assignments
    pim_protected_role_ids = {schedule.get("roleDefinitionId", "") for schedule in eligible_schedules}

    # Check each privileged role
    for role in role_definitions:
        role_name = role.get("displayName", "")
        role_id = role.get("id", "")

        if role_name not in PRIVILEGED_ROLE_NAMES:
            continue

        if role_id not in pim_protected_role_ids:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": f"/roleManagement/directory/roleDefinitions/{role_id}",
                    "resource_name": role_name,
                    "resource_type": "Microsoft.Graph/roleDefinitions",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "role_id": role_id,
                        "role_name": role_name,
                        "pim_configured": False,
                    },
                }
            )

    return findings
