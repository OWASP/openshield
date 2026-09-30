"""AZ-STOR-005: Storage account not using geo-redundant replication."""

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

RULE_ID = "AZ-STOR-005"
RULE_NAME = "Storage Account Not Using Geo-Redundant Replication"
SEVERITY = "MEDIUM"
CATEGORY = "Storage"
FRAMEWORKS = {
    "CIS": "3.8",
    "NIST": "PR.IP-4",
    "ISO27001": "A.8.14",
    "SOC2": "A1.2",
}
DESCRIPTION = (
    "This storage account is configured with a non-geo-redundant replication "
    "SKU ({sku_name}). Locally redundant (LRS) and zone-redundant (ZRS) "
    "storage replicate data only within a single region. A regional outage or "
    "disaster could result in data unavailability or data loss. Geo-redundant "
    "storage (GRS or GZRS) replicates data asynchronously to a secondary "
    "Azure region, protecting against region-wide failures."
)
REMEDIATION = (
    "Change the storage account replication to a geo-redundant SKU such as "
    "Standard_GRS or Standard_GZRS. Navigate to Storage Account > "
    "Configuration > Replication and select Geo-redundant storage (GRS) or "
    "Geo-zone-redundant storage (GZRS). Alternatively, run the remediation "
    "playbook."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_005.sh"

_GEO_REDUNDANT_SKUS = {
    "Standard_GRS",
    "Standard_RAGRS",
    "Standard_GZRS",
    "Standard_RAGZRS",
    "StandardV2_GRS",
    "StandardV2_GZRS",
}


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect storage accounts not configured with geo-redundant replication."""
    findings: List[Dict[str, Any]] = []

    for account in azure_client.get_storage_accounts():
        resource_id = getattr(account, "id", "")
        account_name = getattr(account, "name", "")
        location = getattr(account, "location", "")

        if not resource_id or not account_name:
            continue

        sku = getattr(account, "sku", None)
        sku_name = getattr(sku, "name", "") if sku else ""

        if not sku_name:
            logger.warning(
                "AZ-STOR-005: Could not determine SKU for %s — skipping.",
                account_name,
            )
            continue

        if sku_name in _GEO_REDUNDANT_SKUS:
            continue

        parsed = azure_client.parse_resource_id(resource_id)
        resource_group = parsed.get("resource_group", "")

        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": resource_id,
                "resource_name": account_name,
                "resource_type": "Microsoft.Storage/storageAccounts",
                "description": DESCRIPTION.format(sku_name=sku_name),
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "resource_group": resource_group,
                    "location": location,
                    "current_sku": sku_name,
                    "recommended_sku": "Standard_GRS",
                },
            }
        )

    return findings
