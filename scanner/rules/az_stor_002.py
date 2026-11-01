"""AZ-STOR-002: Storage account not configured for HTTPS-only traffic."""

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

RULE_ID = "AZ-STOR-002"
RULE_NAME = "Storage Account Allows HTTP Traffic (Not HTTPS-Only)"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {"CIS": "3.1", "NIST": "PR.DS-2", "ISO27001": "A.8.24"}
DESCRIPTION = (
    "Storage accounts that do not enforce HTTPS-only traffic allow data to be "
    "transmitted in plaintext over HTTP. This exposes credentials and data to "
    "man-in-the-middle attacks and interception."
)
REMEDIATION = (
    "Enable the 'Secure transfer required' setting on the storage account. "
    "Navigate to Storage Account > Configuration > Secure transfer required and enable it."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_002.sh"
RESOURCE_TYPE = "Microsoft.Storage/storageAccounts"

_UNSET = object()


def _finding(account: Any) -> Dict[str, Any]:
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
    }


def _evaluate_account(azure_client: Any, account: Any, subscription_id: str) -> List[RuleEvaluation]:
    if not getattr(account, "id", None):
        return [missing_resource_id(RULE_ID, RESOURCE_TYPE, subscription_id)]
    value = getattr(account, "enable_https_traffic_only", _UNSET)
    if value is _UNSET:
        return [
            _evaluation(
                account.id,
                EvaluationStatus.UNKNOWN,
                reason_code=MISSING_PROPERTIES,
                reason="enable_https_traffic_only was not returned for the storage account.",
            )
        ]
    evidence = {"enable_https_traffic_only": value}
    if not value:
        return [_evaluation(account.id, EvaluationStatus.FAIL, evidence=evidence, finding=_finding(account))]
    return [_evaluation(account.id, EvaluationStatus.PASS, evidence=evidence)]


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
