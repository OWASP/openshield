"""AZ-SC-003: Azure Container Registry allows anonymous pull."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-SC-003"
RULE_NAME = "Container Registry Allows Anonymous Pull"
SEVERITY = "HIGH"
CATEGORY = "Supply Chain"
FRAMEWORKS = {"CIS": "N/A-SC-003", "NIST": "PR.AC-1", "ISO27001": "A.5.16", "SOC2": "CC6.1"}

DESCRIPTION = (
    "The Azure Container Registry allows anonymous pull, so any client on the network can pull "
    "every image in the registry without authenticating. Repository-scoped tokens cannot limit "
    "this once it is enabled; the setting applies registry-wide. If this registry is intentionally "
    "used for public OCI distribution, treat this finding as an accepted exception rather than a "
    "defect."
)

REMEDIATION = (
    "Disable anonymous pull unless the registry is deliberately used for public distribution: "
    "az acr update --name <registry> --anonymous-pull-enabled false"
)

PLAYBOOK = "playbooks/cli/fix_az_sc_003.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect Container Registries with anonymous pull enabled."""
    findings: List[Dict[str, Any]] = []

    registries = azure_client.get_container_registries()
    if registries is None:
        logger.warning("%s: container registries could not be enumerated", RULE_ID)
        return findings

    for registry in registries:
        props = getattr(registry, "properties", None)
        if props is None:
            continue

        anonymous_pull = getattr(props, "anonymous_pull_enabled", None)
        if anonymous_pull is None:
            logger.warning("%s: anonymous_pull_enabled unknown for %s", RULE_ID, getattr(registry, "name", "?"))
            continue

        if anonymous_pull:
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
                        "anonymous_pull_enabled": True,
                    },
                }
            )

    return findings
