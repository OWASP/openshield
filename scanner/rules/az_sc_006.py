"""AZ-SC-006: Terraform state storage account has no versioning or soft delete."""

import logging
import re
from typing import Any, Dict, List

RULE_ID = "AZ-SC-006"
RULE_NAME = "Terraform State Storage Account Missing Versioning or Soft Delete"
SEVERITY = "HIGH"
CATEGORY = "Supply Chain"
FRAMEWORKS = {"CIS": "N/A-SC-006", "NIST": "PR.IP-4", "ISO27001": "A.8.13", "SOC2": "A1.2"}

DESCRIPTION = (
    "A storage account holding a container that appears to be a Terraform remote state backend "
    "has neither blob versioning nor blob soft delete enabled. Azure does not support these "
    "settings per container, only account-wide. Without either, an overwritten or accidentally "
    "deleted state file cannot be recovered, which can leave Terraform unable to reconcile its "
    "understanding of deployed infrastructure with reality."
)

REMEDIATION = (
    "Enable blob versioning and soft delete on the storage account: "
    "az storage account blob-service-properties update --account-name <account> "
    "--enable-versioning true --enable-delete-retention true --delete-retention-days 30"
)

PLAYBOOK = "playbooks/cli/fix_az_sc_006.sh"

logger = logging.getLogger(__name__)

_TFSTATE_NAME_PATTERN = re.compile(r"tf[-_]?state|terraform[-_]?state", re.IGNORECASE)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect Terraform state storage accounts missing versioning or soft delete."""
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

        has_state_container = any(
            _TFSTATE_NAME_PATTERN.search(getattr(container, "name", "") or "") for container in containers
        )
        if not has_state_container:
            continue

        blob_service = azure_client.get_blob_service_properties(resource_group, account_name)
        if blob_service is None:
            logger.warning("%s: blob service properties unknown for %s", RULE_ID, account_name)
            continue

        versioning_enabled = bool(getattr(blob_service, "is_versioning_enabled", False))
        retention_policy = getattr(blob_service, "delete_retention_policy", None)
        soft_delete_enabled = bool(getattr(retention_policy, "enabled", False)) if retention_policy else False

        if not (versioning_enabled or soft_delete_enabled):
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": account_id,
                    "resource_name": account_name,
                    "resource_type": "Microsoft.Storage/storageAccounts",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": resource_group,
                        "versioning_enabled": versioning_enabled,
                        "soft_delete_enabled": soft_delete_enabled,
                    },
                }
            )

    return findings
