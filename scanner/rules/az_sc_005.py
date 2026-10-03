"""AZ-SC-005: Terraform state storage container is publicly readable."""

import logging
import re
from typing import Any, Dict, List

RULE_ID = "AZ-SC-005"
RULE_NAME = "Terraform State Storage Container Publicly Readable"
SEVERITY = "CRITICAL"
CATEGORY = "Supply Chain"
FRAMEWORKS = {"CIS": "N/A-SC-005", "NIST": "PR.AC-5", "ISO27001": "A.8.20", "SOC2": "CC6.6"}

DESCRIPTION = (
    "A blob container that appears to hold Terraform remote state (matched by name) allows "
    "public read access. Terraform state files commonly contain resource IDs, connection "
    "strings, and in some provider configurations plaintext secrets. Public read access on the "
    "state backend can expose the full infrastructure layout and any secrets it captured."
)

REMEDIATION = (
    "Set the container's public access level to Private and confirm no anonymous read policy is "
    "attached: az storage container set-permission --name <container> --account-name <account> "
    "--public-access off"
)

PLAYBOOK = "playbooks/cli/fix_az_sc_005.sh"

logger = logging.getLogger(__name__)

# Matches container names commonly used for a Terraform remote state backend,
# e.g. "tfstate", "terraform-state", "tf-state-prod".
_TFSTATE_NAME_PATTERN = re.compile(r"tf[-_]?state|terraform[-_]?state", re.IGNORECASE)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect publicly readable blob containers that look like Terraform state backends."""
    findings: List[Dict[str, Any]] = []

    for account in azure_client.get_storage_accounts():
        account_id = getattr(account, "id", "")
        account_name = getattr(account, "name", "")
        if not account_id or not account_name:
            continue

        parsed = azure_client.parse_resource_id(account_id)
        resource_group = parsed.get("resource_group", "")
        if not resource_group:
            continue

        containers = azure_client.get_blob_containers(resource_group, account_name)
        if containers is None:
            logger.warning("%s: blob containers unknown for %s", RULE_ID, account_name)
            continue

        for container in containers:
            container_name = getattr(container, "name", "")
            if not _TFSTATE_NAME_PATTERN.search(container_name):
                continue

            props = getattr(container, "container_properties", None) or container
            public_access = str(getattr(props, "public_access", "") or "").lower()
            if public_access in ("container", "blob"):
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "category": CATEGORY,
                        "resource_id": f"{account_id}/blobServices/default/containers/{container_name}",
                        "resource_name": f"{account_name}/{container_name}",
                        "resource_type": "Microsoft.Storage/storageAccounts/blobServices/containers",
                        "description": DESCRIPTION,
                        "remediation": REMEDIATION,
                        "playbook": PLAYBOOK,
                        "frameworks": FRAMEWORKS,
                        "metadata": {
                            "resource_group": resource_group,
                            "storage_account": account_name,
                            "container_name": container_name,
                            "public_access": public_access,
                        },
                    }
                )

    return findings
