"""AZ-IDN-008: Custom RBAC role with wildcard permissions at subscription scope."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-IDN-008"
RULE_NAME = "Custom RBAC Role with Wildcard Permissions at Subscription Scope"
SEVERITY = "HIGH"
CATEGORY = "Identity"
FRAMEWORKS = {"CIS": "1.23", "NIST": "PR.AC-4", "ISO27001": "A.8.2", "SOC2": "CC6.3"}
DESCRIPTION = (
    "One or more custom RBAC role definitions contain wildcard actions (*) or "
    "overly broad permissions at subscription scope. Custom roles with wildcard "
    "permissions are functionally equivalent to the built-in Owner role but less "
    "visible and harder to audit. They violate the principle of least privilege and "
    "are frequently created as shortcuts that are never cleaned up."
)
REMEDIATION = (
    "Replace wildcard actions with the specific actions required for the role. "
    "Review the role with: az role definition show --name '<role-name>'. "
    "Edit the role definition to replace '*' with explicit action strings. "
    "Use the Azure built-in roles reference to identify the minimum required actions. "
    "If the role is unused, delete it with: az role definition delete --name '<role-name>'."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_008.sh"

logger = logging.getLogger(__name__)

WILDCARD_PATTERNS = ["*", "*/write", "*/delete", "*/action"]


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect custom RBAC roles with wildcard or overly broad permissions."""
    findings: List[Dict[str, Any]] = []

    try:
        from azure.mgmt.authorization import AuthorizationManagementClient

        auth_client = AuthorizationManagementClient(azure_client.credential, subscription_id)
        role_definitions = list(
            auth_client.role_definitions.list(
                scope=f"/subscriptions/{subscription_id}",
                filter="type eq 'CustomRole'",
            )
        )
    except Exception as exc:
        logger.error("AZ-IDN-008: Failed to list custom role definitions: %s", exc)
        return findings

    for role in role_definitions:
        role_name = role.role_name or role.name or "Unknown"
        role_id = role.id or ""
        permissions = role.permissions or []

        flagged_actions = []
        for perm in permissions:
            for action in perm.actions or []:
                if any(action == pattern or action.endswith(pattern) for pattern in WILDCARD_PATTERNS):
                    flagged_actions.append(action)

        if not flagged_actions:
            continue

        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": role_id,
                "resource_name": role_name,
                "resource_type": "Microsoft.Authorization/roleDefinitions",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "role_name": role_name,
                    "role_id": role_id,
                    "flagged_actions": flagged_actions,
                    "assignable_scopes": list(role.assignable_scopes or []),
                },
            }
        )

    return findings
