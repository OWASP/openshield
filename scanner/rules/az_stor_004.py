"""AZ-STOR-004: Storage account diagnostic logging disabled for blob, queue, or table."""

import logging
from typing import Any, Dict, List, Optional, Tuple

from scanner.evaluation import (
    EVIDENCE_UNAVAILABLE,
    MISSING_PROPERTIES,
    EvaluationStatus,
    RuleEvaluation,
    fail_findings,
    inventory_unavailable,
    no_resources_found,
    subscription_scope_id,
)

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
RESOURCE_TYPE = "Microsoft.Storage/storageAccounts"

# Maps service key → (sub-resource path segment, resource_type)
_SERVICES: Dict[str, Tuple[str, str]] = {
    "blob": ("blobServices", "Microsoft.Storage/storageAccounts/blobServices"),
    "queue": ("queueServices", "Microsoft.Storage/storageAccounts/queueServices"),
    "table": ("tableServices", "Microsoft.Storage/storageAccounts/tableServices"),
}


def _service_evaluation(resource_id: str, resource_type: str, status: str, **kwargs: Any) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=RULE_ID, resource_id=resource_id, resource_type=resource_type, status=status, **kwargs
    )


def _finding(resource_id: str, account_name: str, resource_group: str, location: str, service: str) -> Dict[str, Any]:
    svc_path, resource_type = _SERVICES[service]
    return {
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


def _evaluate_account(azure_client: Any, account: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Evaluate diagnostic logging for each of an account's sub-services.

    All three sub-services (blob, queue, table) are evaluated independently,
    each against its own sub-resource ID, because each needs StorageRead,
    StorageWrite, and StorageDelete enabled.

    Three-state return from get_storage_service_logging():
        True  — all three log categories enabled → PASS
        False — one or more categories missing → FAIL with a finding
        None  — permissions error or unexpected failure → UNKNOWN, never
                a finding, to avoid false positives
    """
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

    parsed = azure_client.parse_resource_id(resource_id)
    resource_group = parsed.get("resource_group", "")
    if not resource_group:
        return [
            _evaluation(
                resource_id,
                EvaluationStatus.UNKNOWN,
                reason_code=MISSING_PROPERTIES,
                reason="Resource group could not be parsed from the storage account ID.",
            )
        ]

    evaluations: List[RuleEvaluation] = []
    for service, (svc_path, resource_type) in _SERVICES.items():
        service_id = f"{resource_id}/{svc_path}/default"
        # True = compliant, False = logging incomplete, None = could not determine
        logging_status: Optional[bool] = azure_client.get_storage_service_logging(resource_group, account_name, service)
        evidence = {"service": service, "logging_complete": logging_status}

        if logging_status is False:
            finding = _finding(resource_id, account_name, resource_group, location, service)
            evaluations.append(
                _service_evaluation(
                    service_id, resource_type, EvaluationStatus.FAIL, evidence=evidence, finding=finding
                )
            )
        elif logging_status is True:
            evaluations.append(_service_evaluation(service_id, resource_type, EvaluationStatus.PASS, evidence=evidence))
        else:
            logger.warning(
                "AZ-STOR-004: Could not determine %s logging status for %s "
                "— reporting UNKNOWN. Ensure the service principal has "
                "microsoft.insights/diagnosticSettings/read permission.",
                service,
                account_name,
            )
            evaluations.append(
                _service_evaluation(
                    service_id,
                    resource_type,
                    EvaluationStatus.UNKNOWN,
                    reason_code=EVIDENCE_UNAVAILABLE,
                    reason=f"Diagnostic settings for the {service} service could not be read.",
                )
            )
    return evaluations


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
