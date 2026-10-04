"""AZ-STOR-005: Storage account not using geo-redundant replication."""

import logging
from typing import Any, Dict, List

from scanner.evaluation import (
    MISSING_PROPERTIES,
    EvaluationStatus,
    RuleEvaluation,
    fail_findings,
    inventory_unavailable,
    no_resources_found,
    subscription_scope_id,
)

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
RESOURCE_TYPE = "Microsoft.Storage/storageAccounts"

_GEO_REDUNDANT_SKUS = {
    "Standard_GRS",
    "Standard_RAGRS",
    "Standard_GZRS",
    "Standard_RAGZRS",
    "StandardV2_GRS",
    "StandardV2_GZRS",
}


def _finding(azure_client: Any, resource_id: str, account_name: str, location: str, sku_name: str) -> Dict[str, Any]:
    parsed = azure_client.parse_resource_id(resource_id)
    resource_group = parsed.get("resource_group", "")
    return {
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


def _evaluate_account(azure_client: Any, account: Any, subscription_id: str) -> List[RuleEvaluation]:
    resource_id = getattr(account, "id", "")
    account_name = getattr(account, "name", "")
    location = getattr(account, "location", "")

    if not resource_id or not account_name:
        return [
            _evaluation(
                resource_id or subscription_scope_id(subscription_id),
                EvaluationStatus.UNKNOWN,
                reason_code=MISSING_PROPERTIES,
                reason="Storage account was returned without an ID or name.",
            )
        ]

    sku = getattr(account, "sku", None)
    sku_name = getattr(sku, "name", "") if sku else ""

    if not sku_name:
        logger.warning(
            "AZ-STOR-005: Could not determine SKU for %s — reporting UNKNOWN.",
            account_name,
        )
        return [
            _evaluation(
                resource_id,
                EvaluationStatus.UNKNOWN,
                reason_code=MISSING_PROPERTIES,
                reason="Storage account SKU was not returned.",
            )
        ]

    evidence = {"sku": sku_name}
    if sku_name in _GEO_REDUNDANT_SKUS:
        return [_evaluation(resource_id, EvaluationStatus.PASS, evidence=evidence)]
    finding = _finding(azure_client, resource_id, account_name, location, sku_name)
    return [_evaluation(resource_id, EvaluationStatus.FAIL, evidence=evidence, finding=finding)]


def _evaluation(resource_id: str, status: str, **kwargs: Any) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=RULE_ID, resource_id=resource_id, resource_type=RESOURCE_TYPE, status=status, **kwargs
    )


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return the findings attached to this rule's FAIL evaluations."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report a status for every storage account, PASS included."""
    accounts = azure_client.list_storage_accounts()
    if accounts is None:
        return [inventory_unavailable(RULE_ID, RESOURCE_TYPE, subscription_id)]
    if not accounts:
        return [no_resources_found(RULE_ID, RESOURCE_TYPE, subscription_id)]
    evaluations: List[RuleEvaluation] = []
    for account in accounts:
        evaluations.extend(_evaluate_account(azure_client, account, subscription_id))
    return evaluations
