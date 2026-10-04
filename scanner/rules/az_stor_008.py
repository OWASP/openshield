"""AZ-STOR-008: required customer-managed key protection is absent."""

import logging
from typing import Any, Dict, List

from scanner.evaluation import (
    MISSING_PROPERTIES,
    EvaluationStatus,
    RuleEvaluation,
    fail_findings,
    inventory_unavailable,
    missing_resource_id,
    no_resources_found,
)
from scanner.rules._storage_common import policy_exemption

logger = logging.getLogger(__name__)

RULE_ID = "AZ-STOR-008"
RULE_NAME = "Required Storage Customer-Managed Key Protection Missing"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {"CIS": "N/A-STOR-008", "NIST": "N/A-STOR-008", "ISO27001": "N/A-STOR-008", "SOC2": "N/A-STOR-008"}
DESCRIPTION = "This explicitly protected storage account is not using a customer-managed encryption key."
REMEDIATION = (
    "Configure storage encryption with an approved Key Vault customer-managed key "
    "after validating key access and rotation ownership."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_008.sh"
RESOURCE_TYPE = "Microsoft.Storage/storageAccounts"

_REQUIREMENT_TAG = "oshield:cmk-required"


def _finding(account: Any, key_source: Any) -> Dict[str, Any]:
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
        "metadata": {"key_source": str(key_source), "requirement_tag": "oshield:cmk-required"},
    }


def _evaluate_account(azure_client: Any, account: Any, subscription_id: str) -> List[RuleEvaluation]:
    if not getattr(account, "id", None):
        return [missing_resource_id(RULE_ID, RESOURCE_TYPE, subscription_id)]
    exemption = policy_exemption(account, _REQUIREMENT_TAG)
    if exemption:
        return [
            _evaluation(
                account.id,
                EvaluationStatus.NOT_APPLICABLE,
                reason_code=exemption,
                reason=f"Customer-managed keys are not required by the {_REQUIREMENT_TAG} tag.",
            )
        ]
    encryption = getattr(account, "encryption", None)
    key_source = getattr(encryption, "key_source", None) if encryption else None
    if key_source is None:
        logger.warning("%s: encryption source unavailable; reporting UNKNOWN", RULE_ID)
        return [
            _evaluation(
                account.id,
                EvaluationStatus.UNKNOWN,
                reason_code=MISSING_PROPERTIES,
                reason="Storage account encryption key source was not returned.",
            )
        ]
    evidence = {"key_source": str(key_source)}
    source = str(key_source).strip().lower()
    if source in {"microsoft.keyvault", "keyvault", "microsoft.keyvaultmanaged"}:
        return [_evaluation(account.id, EvaluationStatus.PASS, evidence=evidence)]
    if source != "microsoft.storage":
        logger.warning("%s: unknown encryption source %r; reporting UNKNOWN", RULE_ID, key_source)
        return [
            _evaluation(
                account.id,
                EvaluationStatus.UNKNOWN,
                reason_code="UNRECOGNIZED_KEY_SOURCE",
                reason=f"Unrecognized encryption key source {str(key_source)!r}.",
                evidence=evidence,
            )
        ]
    return [_evaluation(account.id, EvaluationStatus.FAIL, evidence=evidence, finding=_finding(account, key_source))]


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
