"""AZ-STOR-004: Storage account diagnostic logging disabled for blob, queue, or table."""

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Required module-level constants ─────────────────────────────────────────

RULE_ID = "AZ-STOR-004"
RULE_NAME = "Storage Account Diagnostic Logging Disabled"
SEVERITY = "MEDIUM"
CATEGORY = "Storage"
FRAMEWORKS = {
    "CIS": "3.3",
    "NIST": "DE.CM-7",
    "ISO27001": "A.8.15",
    "SOC2": "CC7.2",
}
DESCRIPTION = (
    "Azure Monitor diagnostic logging is not fully enabled for the {service} "
    "service on this storage account. StorageRead, StorageWrite, and "
    "StorageDelete must all be enabled. Without logging, operations on this "
    "service cannot be detected or investigated, making it impossible to "
    "identify data exfiltration or unauthorised access. CIS Azure Benchmark "
    "3.3 requires logging for blob, queue, and table services for read, write, "
    "and delete requests."
)
REMEDIATION = (
    "Enable Azure Monitor diagnostic settings on the storage account's "
    "{service} service with StorageRead, StorageWrite, and StorageDelete all "
    "set to enabled. Navigate to: Storage Account > Monitoring > "
    "Diagnostic settings > {service} > Add diagnostic setting, then check "
    "StorageRead, StorageWrite, and StorageDelete."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_004.sh"

# Maps service key → (sub-resource path segment, resource_type)
_SERVICES: Dict[str, Tuple[str, str]] = {
    "blob": ("blobServices", "Microsoft.Storage/storageAccounts/blobServices"),
    "queue": ("queueServices", "Microsoft.Storage/storageAccounts/queueServices"),
    "table": ("tableServices", "Microsoft.Storage/storageAccounts/tableServices"),
}


# ── Required scan function ───────────────────────────────────────────────────


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect storage account services with incomplete diagnostic logging.

    For each storage account, all three sub-services (blob, queue, table) are
    checked independently. A separate finding is emitted for each service that
    does not have StorageRead, StorageWrite, and StorageDelete all enabled.

    Three-state return from get_storage_service_logging():
        True  — all three log categories enabled → skip (compliant)
        False — one or more categories missing → create finding
        None  — permissions error or unexpected failure → skip with warning
                to avoid false positives

    Args:
        azure_client:    An AzureClient instance with all SDK clients
                         pre-configured.
        subscription_id: The Azure subscription ID being scanned.

    Returns:
        A list of finding dicts — one per storage service sub-resource that
        does not have full diagnostic logging. Services that could not be
        checked are skipped and logged as warnings.
    """
    findings: List[Dict[str, Any]] = []

    for account in azure_client.get_storage_accounts():
        resource_id = getattr(account, "id", "")
        account_name = getattr(account, "name", "")
        location = getattr(account, "location", "")

        if not resource_id or not account_name:
            continue

        parsed = azure_client.parse_resource_id(resource_id)
        resource_group = parsed.get("resource_group", "")
        if not resource_group:
            continue

        for service, (svc_path, resource_type) in _SERVICES.items():
            # True = compliant, False = logging incomplete, None = could not determine
            logging_status: Optional[bool] = azure_client.get_storage_service_logging(
                resource_group, account_name, service
            )

            if logging_status is None:
                logger.warning(
                    "AZ-STOR-004: Could not determine %s logging status for %s "
                    "— skipping. Ensure the service principal has "
                    "microsoft.insights/diagnosticSettings/read permission.",
                    service,
                    account_name,
                )
                continue

            if logging_status is False:
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "category": CATEGORY,
                        "resource_id": f"{resource_id}/{svc_path}/default",
                        "resource_name": f"{account_name}/{svc_path}",
                        "resource_type": resource_type,
                        "description": DESCRIPTION.format(service=service),
                        "remediation": REMEDIATION.format(service=service),
                        "playbook": PLAYBOOK,
                        "frameworks": FRAMEWORKS,
                        "metadata": {
                            "resource_group": resource_group,
                            "location": location,
                            "service": service,
                        },
                    }
                )

    return findings
