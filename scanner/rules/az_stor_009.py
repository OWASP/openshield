"""AZ-STOR-009: required blob-container immutability is absent."""

import logging
from typing import Any, Dict, List

from scanner.azure_client import enum_str
from scanner.rules._storage_common import policy_required

logger = logging.getLogger(__name__)

RULE_ID = "AZ-STOR-009"
RULE_NAME = "Required Blob Container Immutability Missing"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {"CIS": "N/A-STOR-009", "NIST": "N/A-STOR-009", "ISO27001": "N/A-STOR-009", "SOC2": "N/A-STOR-009"}
DESCRIPTION = "This explicitly protected blob container has no effective immutability policy."
REMEDIATION = (
    "Configure and, where required, lock a time-based immutability policy for the "
    "container after confirming retention requirements."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_009.sh"


def _container_properties(container: Any) -> Any:
    return getattr(container, "container_properties", None) or container


def _has_immutability(container: Any) -> bool:
    props = _container_properties(container)
    policy = getattr(container, "immutability_policy", None) or getattr(props, "immutability_policy", None)
    if policy is None:
        return False
    state = enum_str(getattr(policy, "state", None)).lower()
    retention = getattr(policy, "immutability_period_since_creation_in_days", None)
    return state in {"locked", "unlocked"} and isinstance(retention, int) and retention > 0


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for account in azure_client.get_storage_accounts():
        resource_id = getattr(account, "id", "")
        account_name = getattr(account, "name", "")
        parsed = azure_client.parse_resource_id(resource_id)
        resource_group = parsed.get("resource_group", "")
        if not resource_group or not account_name:
            continue
        containers = azure_client.get_blob_containers(resource_group, account_name)
        if containers is None:
            logger.warning("%s: blob containers unavailable for %s; skipping", RULE_ID, account_name)
            continue
        account_required = policy_required(account, "oshield:immutability-required")
        for container in containers:
            container_required = policy_required(container, "oshield:immutability-required")
            if not account_required and not container_required:
                continue
            if _has_immutability(container):
                continue
            name = getattr(container, "name", "")
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": f"{resource_id}/blobServices/default/containers/{name}",
                    "resource_name": f"{account_name}/{name}",
                    "resource_type": "Microsoft.Storage/storageAccounts/blobServices/containers",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {"requirement_tag": "oshield:immutability-required"},
                }
            )
    return findings
