"""AZ-SC-006: Terraform state storage account has no versioning or soft delete."""

import logging
import re
from typing import Any, Dict, List

from scanner.evaluation import EVIDENCE_UNAVAILABLE, NO_RESOURCES_FOUND, EvaluationStatus, RuleEvaluation, fail_findings
from scanner.rules._supply_chain_common import STORAGE_ACCOUNT_TYPE, evaluate_storage_accounts, evaluation, failed

RULE_ID = "AZ-SC-006"
RULE_NAME = "Terraform State Storage Account Missing Versioning or Soft Delete"
SEVERITY = "HIGH"
CATEGORY = "Supply Chain"
FRAMEWORKS = {"CIS": "N/A-SC-006", "NIST": "PR.IP-4", "ISO27001": "A.8.13", "SOC2": "A1.2"}

DESCRIPTION = (
    "A storage account holding a container that appears to be a Terraform remote state backend "
    "has neither blob versioning nor blob soft delete enabled. Azure does not support these "
    "settings per container, only account-wide. Without either, an overwritten or accidentally "
    "deleted state file cannot be recovered, which can leave Terraform unable to reconcile its "
    "understanding of deployed infrastructure with reality."
)

REMEDIATION = (
    "Enable blob versioning and soft delete on the storage account: "
    "az storage account blob-service-properties update --account-name <account> "
    "--enable-versioning true --enable-delete-retention true --delete-retention-days 30"
)

PLAYBOOK = "playbooks/cli/fix_az_sc_006.sh"

logger = logging.getLogger(__name__)

_TFSTATE_NAME_PATTERN = re.compile(r"tf[-_]?state|terraform[-_]?state", re.IGNORECASE)


def _unknown(account_id: str, reason: str) -> RuleEvaluation:
    return evaluation(
        RULE_ID,
        account_id,
        STORAGE_ACCOUNT_TYPE,
        EvaluationStatus.UNKNOWN,
        reason_code=EVIDENCE_UNAVAILABLE,
        reason=reason,
    )


def _judge_account(
    azure_client: Any, account: Any, account_id: str, account_name: str, resource_group: str
) -> List[RuleEvaluation]:
    containers = azure_client.get_blob_containers(resource_group, account_name)
    if containers is None:
        logger.warning("%s: blob containers unknown for %s", RULE_ID, account_name)
        return [_unknown(account_id, "Blob containers could not be listed for the storage account.")]
    if not any(_TFSTATE_NAME_PATTERN.search(getattr(c, "name", "") or "") for c in containers):
        return [
            evaluation(
                RULE_ID,
                account_id,
                STORAGE_ACCOUNT_TYPE,
                EvaluationStatus.NOT_APPLICABLE,
                reason_code=NO_RESOURCES_FOUND,
                reason="The storage account has no container named like a Terraform state backend.",
            )
        ]

    blob_service = azure_client.get_blob_service_properties(resource_group, account_name)
    if blob_service is None:
        logger.warning("%s: blob service properties unknown for %s", RULE_ID, account_name)
        return [_unknown(account_id, "Blob service properties could not be read for the storage account.")]

    versioning_enabled = bool(getattr(blob_service, "is_versioning_enabled", False))
    retention_policy = getattr(blob_service, "delete_retention_policy", None)
    soft_delete_enabled = bool(getattr(retention_policy, "enabled", False)) if retention_policy else False
    evidence = {"versioning_enabled": versioning_enabled, "soft_delete_enabled": soft_delete_enabled}
    if versioning_enabled or soft_delete_enabled:
        return [evaluation(RULE_ID, account_id, STORAGE_ACCOUNT_TYPE, EvaluationStatus.PASS, evidence=evidence)]

    finding = {
        "rule_id": RULE_ID,
        "rule_name": RULE_NAME,
        "severity": SEVERITY,
        "category": CATEGORY,
        "resource_id": account_id,
        "resource_name": account_name,
        "resource_type": STORAGE_ACCOUNT_TYPE,
        "description": DESCRIPTION,
        "remediation": REMEDIATION,
        "playbook": PLAYBOOK,
        "frameworks": FRAMEWORKS,
        "metadata": {"resource_group": resource_group, **evidence},
    }
    return [failed(RULE_ID, finding, evidence)]


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return the findings attached to this rule's FAIL evaluations."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report a status for every storage account, judging only those holding Terraform state."""
    return evaluate_storage_accounts(
        RULE_ID,
        azure_client,
        subscription_id,
        lambda account, account_id, name, resource_group: _judge_account(
            azure_client, account, account_id, name, resource_group
        ),
    )
