"""AZ-STOR-003: Storage account has no lifecycle management policy configured."""

import logging
from typing import Any, Dict, List, Optional

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

# subscription_id is received by scan() and passed to AzureClient methods
# that need explicit scope. It is not read from the environment here —
# the engine always passes it as a parameter. Never read os.environ directly.

# ── Required module-level constants ─────────────────────────────────────────

RULE_ID = "AZ-STOR-003"
RULE_NAME = "Storage Account Has No Lifecycle Management Policy"
SEVERITY = "MEDIUM"
CATEGORY = "Storage"
FRAMEWORKS = {
    "CIS": "3.7",
    "NIST": "PR.DS-3",
    "ISO27001": "A.7.10",
}
DESCRIPTION = (
    "The storage account has no lifecycle management policy configured. "
    "Without a lifecycle policy, blobs accumulate indefinitely — old data "
    "that is no longer needed remains accessible, increasing storage costs "
    "and the attack surface. A compromised account exposes all historical "
    "data with no automatic expiry or tiering in place."
)
REMEDIATION = (
    "Create a lifecycle management policy on the storage account that "
    "transitions blobs to cooler tiers (Cool, Archive) after a defined "
    "number of days, and deletes blobs that exceed the organisation's "
    "maximum retention period. Navigate to: Storage Account > "
    "Data management > Lifecycle management > Add a rule."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_003.sh"
RESOURCE_TYPE = "Microsoft.Storage/storageAccounts"


def _finding(resource_id: str, account_name: str, resource_group: str, location: str) -> Dict[str, Any]:
    return {
        "rule_id": RULE_ID,
        "rule_name": RULE_NAME,
        "severity": SEVERITY,
        "category": CATEGORY,
        "resource_id": resource_id,
        "resource_name": account_name,
        "resource_type": "Microsoft.Storage/storageAccounts",
        "description": DESCRIPTION,
        "remediation": REMEDIATION,
        "playbook": PLAYBOOK,
        "frameworks": FRAMEWORKS,
        "metadata": {
            "resource_group": resource_group,
            "location": location,
        },
    }


def _evaluate_account(azure_client: Any, account: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Evaluate one account's lifecycle management policy.

    The Azure Storage Management SDK exposes lifecycle policies via
    ``management_policies.get(resource_group, account_name)``.
    A ResourceNotFound (404) response means no policy exists — this is
    the condition we flag as MEDIUM severity.

    Three-state return from get_storage_lifecycle_policy():
        True  — policy exists and has rules → PASS
        False — no policy exists → FAIL with a finding
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

    # True = compliant, False = no policy, None = could not determine
    policy_status: Optional[bool] = azure_client.get_storage_lifecycle_policy(resource_group, account_name)
    evidence = {"lifecycle_policy": policy_status}

    if policy_status is False:
        finding = _finding(resource_id, account_name, resource_group, location)
        return [_evaluation(resource_id, EvaluationStatus.FAIL, evidence=evidence, finding=finding)]
    if policy_status is True:
        return [_evaluation(resource_id, EvaluationStatus.PASS, evidence=evidence)]

    # Permissions error or unexpected SDK failure: report it rather than
    # guess either way.
    logger.warning(
        "AZ-STOR-003: Could not determine lifecycle policy for %s "
        "— reporting UNKNOWN. Ensure the service principal has "
        "Microsoft.Storage/storageAccounts/managementPolicies/read "
        "permission.",
        account_name,
    )
    return [
        _evaluation(
            resource_id,
            EvaluationStatus.UNKNOWN,
            reason_code=EVIDENCE_UNAVAILABLE,
            reason="Lifecycle management policy could not be read.",
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
