"""AZ-IDN-001: Service principal assigned Owner role at subscription scope."""

from typing import Any, Dict, List

RULE_ID = "AZ-IDN-001"
RULE_NAME = "Service Principal Assigned Owner Role at Subscription Scope"
SEVERITY = "HIGH"
CATEGORY = "Identity"
FRAMEWORKS = {"CIS": "1.24", "NIST": "PR.AC-4", "ISO27001": "A.8.2"}
DESCRIPTION = (
    "A service principal holds the Owner role at subscription scope, granting it "
    "full control over all resources and the ability to assign roles to other principals. "
    "This violates the principle of least privilege and represents a critical blast-radius "
    "risk if the service principal credentials are compromised."
)
REMEDIATION = (
    "Replace the Owner role assignment with a narrower built-in role (e.g., Contributor, "
    "or a custom role) that covers only the required permissions. "
    "Audit and rotate the service principal's client secret or certificate."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_001.sh"

# Azure built-in Owner role definition GUID
OWNER_ROLE_GUID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect service principals holding the Owner role at subscription scope."""
    findings: List[Dict[str, Any]] = []

    for assignment in azure_client.get_service_principals():
        role_def_id = getattr(assignment, "role_definition_id", "") or ""
        if not role_def_id.endswith(OWNER_ROLE_GUID):
            continue

        principal_id = getattr(assignment, "principal_id", "unknown")
        resource_id = getattr(assignment, "id", "")

        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": resource_id,
                "resource_name": principal_id,
                "resource_type": "Microsoft.Authorization/roleAssignments",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "principal_id": principal_id,
                    "scope": getattr(assignment, "scope", ""),
                },
            }
        )

    return findings
