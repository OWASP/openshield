"""AZ-STOR-006: Storage account shared-key authorization remains enabled."""

import logging
from typing import Any, Dict, List

from scanner.evaluation import (
    EvaluationStatus,
    RuleEvaluation,
    fail_findings,
    inventory_unavailable,
    missing_resource_id,
    no_resources_found,
)

logger = logging.getLogger(__name__)

RULE_ID = "AZ-STOR-006"
RULE_NAME = "Storage Account Shared-Key Authorization Enabled"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {
    "CIS": "N/A-STOR-006",
    "NIST": "N/A-STOR-006",
    "ISO27001": "N/A-STOR-006",
    "SOC2": "N/A-STOR-006",
}
DESCRIPTION = (
    "Shared-key authorization is enabled on this storage account. Shared keys "
    "are long-lived account-wide credentials and bypass identity-based access "
    "controls when disclosed."
)
REMEDIATION = (
    "Disable shared-key authorization after confirming that all clients use "
    "Microsoft Entra ID or an approved alternative. Navigate to Storage Account "
    "> Configuration > Allow storage account key access and set it to Disabled."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_006.sh"
RESOURCE_TYPE = "Microsoft.Storage/storageAccounts"


def _finding(account: Any, state: Any) -> Dict[str, Any]:
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
        "metadata": {"allow_shared_key_access": state},
    }


def _evaluate_account(azure_client: Any, account: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Fail accounts where shared-key access is enabled or unset.

    Azure documents allow_shared_key_access=None as equivalent to True:
    an account with no explicit setting permits Shared Key authorization.
    Only False (explicitly disabled) is compliant.
    """
    if not getattr(account, "id", None):
        return [missing_resource_id(RULE_ID, RESOURCE_TYPE, subscription_id)]
    state = getattr(account, "allow_shared_key_access", None)
    evidence = {"allow_shared_key_access": state}
    if state is False:
        return [_evaluation(account.id, EvaluationStatus.PASS, evidence=evidence)]
    return [_evaluation(account.id, EvaluationStatus.FAIL, evidence=evidence, finding=_finding(account, state))]


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
