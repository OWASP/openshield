"""AZ-SC-001: Azure Container Registry admin user enabled."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-SC-001"
RULE_NAME = "Container Registry Admin User Enabled"
SEVERITY = "HIGH"
CATEGORY = "Supply Chain"
FRAMEWORKS = {"CIS": "N/A-SC-001", "NIST": "PR.AC-1", "ISO27001": "A.5.16", "SOC2": "CC6.1"}

DESCRIPTION = (
    "The Azure Container Registry has the admin user enabled. The admin account is a single "
    "shared, non-attributable credential that bypasses Azure RBAC entirely, so registry pushes "
    "and pulls made with it cannot be tied to an individual identity or revoked without affecting "
    "every other user of the same credential."
)

REMEDIATION = (
    "Disable the admin user and authenticate to the registry with Azure AD identities or a "
    "managed identity instead: az acr update --name <registry> --admin-enabled false"
)

PLAYBOOK = "playbooks/cli/fix_az_sc_001.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect Container Registries with the admin user enabled."""
    findings: List[Dict[str, Any]] = []

    registries = azure_client.get_container_registries()
    if registries is None:
        logger.warning("%s: container registries could not be enumerated", RULE_ID)
        return findings

    for registry in registries:
        props = getattr(registry, "properties", None)
        if props is None:
            continue

        admin_enabled = getattr(props, "admin_user_enabled", None)
        if admin_enabled is None:
            logger.warning("%s: admin_user_enabled unknown for %s", RULE_ID, getattr(registry, "name", "?"))
            continue

        if admin_enabled:
            parsed = azure_client.parse_resource_id(getattr(registry, "id", ""))
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": getattr(registry, "id", ""),
                    "resource_name": getattr(registry, "name", ""),
                    "resource_type": "Microsoft.ContainerRegistry/registries",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": parsed.get("resource_group", ""),
                        "admin_user_enabled": True,
                    },
                }
            )

    return findings
