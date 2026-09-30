"""AZ-SC-002: Azure Container Registry allows public network access."""

import logging
from typing import Any, Dict, List

from scanner.azure_client import enum_str

RULE_ID = "AZ-SC-002"
RULE_NAME = "Container Registry Public Network Access Enabled"
SEVERITY = "HIGH"
CATEGORY = "Supply Chain"
FRAMEWORKS = {"CIS": "N/A-SC-002", "NIST": "PR.AC-5", "ISO27001": "A.8.20", "SOC2": "CC6.6"}

DESCRIPTION = (
    "The Azure Container Registry is reachable from the public internet. A registry that holds "
    "the container images an organization builds and deploys should only be reachable from "
    "trusted networks, the same way source code and build systems are."
)

REMEDIATION = (
    "Disable public network access and expose the registry through a private endpoint instead: "
    "az acr update --name <registry> --public-network-enabled false"
)

PLAYBOOK = "playbooks/cli/fix_az_sc_002.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect Container Registries with public network access enabled."""
    findings: List[Dict[str, Any]] = []

    registries = azure_client.get_container_registries()
    if registries is None:
        logger.warning("%s: container registries could not be enumerated", RULE_ID)
        return findings

    for registry in registries:
        props = getattr(registry, "properties", None)
        if props is None:
            continue

        public_access = enum_str(getattr(props, "public_network_access", None))
        if not public_access:
            logger.warning("%s: public_network_access unknown for %s", RULE_ID, getattr(registry, "name", "?"))
            continue

        if public_access.lower() == "enabled":
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
                        "public_network_access": public_access,
                    },
                }
            )

    return findings
