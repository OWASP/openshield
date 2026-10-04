"""AZ-STOR-007: Storage account permits a TLS version below TLS 1.2."""

import logging
from typing import Any, Dict, List

from scanner.azure_client import enum_str
from scanner.evaluation import (
    EvaluationStatus,
    RuleEvaluation,
    fail_findings,
    inventory_unavailable,
    missing_resource_id,
    no_resources_found,
)

logger = logging.getLogger(__name__)

RULE_ID = "AZ-STOR-007"
RULE_NAME = "Storage Account Allows TLS Below 1.2"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {
    "CIS": "N/A-STOR-007",
    "NIST": "N/A-STOR-007",
    "ISO27001": "N/A-STOR-007",
    "SOC2": "N/A-STOR-007",
}
DESCRIPTION = (
    "The storage account permits a minimum TLS version below TLS 1.2. Older "
    "protocols no longer provide an approved transport-security baseline."
)
REMEDIATION = (
    "Set the storage account minimum TLS version to TLS 1.2 or later. Navigate "
    "to Storage Account > Configuration > Minimum TLS version."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_007.sh"
RESOURCE_TYPE = "Microsoft.Storage/storageAccounts"

_INSECURE_TLS = {"TLS1_0", "TLS1_1", "1.0", "1.1"}
_SECURE_TLS = {"TLS1_2", "TLS1_3", "1.2", "1.3"}


def _finding(account: Any, value: Any) -> Dict[str, Any]:
    return {
        "rule_id": RULE_ID,
        "rule_name": RULE_NAME,
        "severity": SEVERITY,
        "category": CATEGORY,
        "resource_id": account.id,
        "resource_name": account.name,
        "resource_type": "Microsoft.Storage/storageAccounts",
        "description": DESCRIPTION,
        "remediation": REMEDIATION,
        "playbook": PLAYBOOK,
        "frameworks": FRAMEWORKS,
        "metadata": {
            "minimum_tls_version": str(value),
            "approved_minimum": "TLS1_2",
        },
    }


def _evaluate_account(azure_client: Any, account: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Fail accounts with TLS below 1.2 or with an unset minimum TLS version.

    Azure documents an unset minimum_tls_version as TLS 1.0, so None is
    treated as insecure. enum_str() is used to handle SDK enum objects
    (e.g. MinimumTlsVersion.TLS1_0) so they compare correctly against the
    known-insecure set instead of producing a string like
    'MinimumTlsVersion.TLS1_0'. A value in neither set is UNKNOWN.
    """
    if not getattr(account, "id", None):
        return [missing_resource_id(RULE_ID, RESOURCE_TYPE, subscription_id)]
    value = getattr(account, "minimum_tls_version", None)
    if value is None:
        normalized = "TLS1_0"
    else:
        normalized = enum_str(value).strip().upper()
    evidence = {"minimum_tls_version": str(value), "normalized": normalized}
    if normalized in _INSECURE_TLS:
        return [_evaluation(account.id, EvaluationStatus.FAIL, evidence=evidence, finding=_finding(account, value))]
    if normalized in _SECURE_TLS:
        return [_evaluation(account.id, EvaluationStatus.PASS, evidence=evidence)]
    return [
        _evaluation(
            account.id,
            EvaluationStatus.UNKNOWN,
            reason_code="UNRECOGNIZED_TLS_VERSION",
            reason=f"Unrecognized minimum_tls_version {normalized!r}.",
            evidence=evidence,
        )
    ]


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
