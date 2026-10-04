"""AZ-STOR-001: Storage account with public blob access enabled."""

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

RULE_ID = "AZ-STOR-001"
RULE_NAME = "Public Blob Access Enabled on Storage Account"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {"CIS": "3.5", "NIST": "PR.AC-3", "ISO27001": "A.8.3"}
DESCRIPTION = (
    "Storage accounts with public blob access enabled allow unauthenticated "
    "read access to blob data over the internet. This setting can expose "
    "sensitive files, backups, or configuration data to any external actor."
)
REMEDIATION = (
    "Disable public blob access on the storage account. "
    "Navigate to Storage Account > Configuration > Blob public access and set it to Disabled."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_001.sh"
RESOURCE_TYPE = "Microsoft.Storage/storageAccounts"


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
    value = getattr(account, "allow_blob_public_access", None)
    if value is None:
        # Older API versions defaulted an unset value to allowed, so an
        # unset value is not evidence of compliance.
        return [
            _evaluation(
                account.id,
                EvaluationStatus.UNKNOWN,
                reason_code=MISSING_PROPERTIES,
                reason="allow_blob_public_access is not set on the storage account.",
            )
        ]
    evidence = {"allow_blob_public_access": value}
    if value:
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
