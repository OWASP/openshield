"""AZ-IDN-005: Guest users with high privilege roles in Entra ID."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-IDN-005"
RULE_NAME = "Guest User with High Privilege Role in Entra ID"
SEVERITY = "HIGH"
CATEGORY = "Identity"
FRAMEWORKS = {"CIS": "1.3", "NIST": "PR.AC-4", "ISO27001": "A.8.2", "SOC2": "CC6.3"}
DESCRIPTION = (
    "One or more guest user accounts (userType = Guest) have been assigned high "
    "privilege roles in Entra ID. Guest accounts originate from outside the "
    "organisation and should never hold privileged roles. A compromised guest "
    "account with admin rights gives an external attacker full control of the "
    "Azure tenant."
)
REMEDIATION = (
    "Remove privileged role assignments from all guest accounts. Navigate to: "
    "Entra ID > Roles and administrators > [role name] > Assignments. "
    "For each guest account found, click the assignment and select Remove. "
    "Consider converting the guest to a member account or using a dedicated "
    "internal service account for any legitimate administrative need."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_005.sh"

logger = logging.getLogger(__name__)

HIGH_RISK_ROLES = [
    "Global Administrator",
    "Privileged Role Administrator",
    "User Administrator",
    "Security Administrator",
    "Exchange Administrator",
]


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect guest users assigned to high privilege roles in Entra ID."""
    findings: List[Dict[str, Any]] = []

    try:
        import requests

        token = azure_client.credential.get_token("https://graph.microsoft.com/.default")
        headers = {"Authorization": f"Bearer {token.token}"}

        response = requests.get(
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions",
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()
        role_definitions = {
            r["id"]: r["displayName"]
            for r in response.json().get("value", [])
            if r.get("displayName") in HIGH_RISK_ROLES
        }

        if not role_definitions:
            return findings

        response = requests.get(
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments",
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()
        assignments = response.json().get("value", [])

    except Exception as exc:
        logger.error("AZ-IDN-005: Failed to fetch data from Graph API: %s", exc)
        logger.warning(
            "AZ-IDN-005: Ensure the service principal has RoleManagement.Read.Directory permission on Microsoft Graph."
        )
        return findings

    for assignment in assignments:
        role_def_id = assignment.get("roleDefinitionId", "")
        if role_def_id not in role_definitions:
            continue

        principal_id = assignment.get("principalId", "")
        if not principal_id:
            continue

        try:
            user_resp = requests.get(
                f"https://graph.microsoft.com/v1.0/users/{principal_id}"
                "?$select=id,displayName,userPrincipalName,userType",
                headers=headers,
                timeout=30,
            )
            if user_resp.status_code != 200:
                continue
            user = user_resp.json()
        except Exception:
            continue

        if user.get("userType") != "Guest":
            continue

        role_name = role_definitions[role_def_id]
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": (f"/users/{principal_id}/roleAssignments/{assignment.get('id', '')}"),
                "resource_name": user.get("displayName", user.get("userPrincipalName", principal_id)),
                "resource_type": "Microsoft.Graph/users",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "user_id": principal_id,
                    "user_principal_name": user.get("userPrincipalName", ""),
                    "user_type": "Guest",
                    "role_name": role_name,
                    "role_definition_id": role_def_id,
                },
            }
        )

    return findings
