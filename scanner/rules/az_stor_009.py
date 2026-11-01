"""AZ-STOR-009: required blob-container immutability is absent."""

import logging
from typing import Any, Dict, List

from scanner.azure_client import enum_str
from scanner.evaluation import (
    APPROVED_EXCEPTION,
    EVIDENCE_UNAVAILABLE,
    MISSING_PROPERTIES,
    NO_RESOURCES_FOUND,
    POLICY_NOT_REQUIRED,
    EvaluationStatus,
    RuleEvaluation,
    fail_findings,
    inventory_unavailable,
    no_resources_found,
    subscription_scope_id,
)
from scanner.rules._storage_common import policy_exemption

logger = logging.getLogger(__name__)

RULE_ID = "AZ-STOR-009"
RULE_NAME = "Required Blob Container Immutability Missing"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {"CIS": "N/A-STOR-009", "NIST": "N/A-STOR-009", "ISO27001": "N/A-STOR-009", "SOC2": "N/A-STOR-009"}
DESCRIPTION = "This explicitly protected blob container has no effective immutability policy."
REMEDIATION = (
    "Configure and, where required, lock a time-based immutability policy for the "
    "container after confirming retention requirements."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_009.sh"
RESOURCE_TYPE = "Microsoft.Storage/storageAccounts"
CONTAINER_RESOURCE_TYPE = "Microsoft.Storage/storageAccounts/blobServices/containers"
_REQUIREMENT_TAG = "oshield:immutability-required"


def _container_properties(container: Any) -> Any:
    return getattr(container, "container_properties", None) or container


def _has_immutability(container: Any) -> bool:
    props = _container_properties(container)
    policy = getattr(container, "immutability_policy", None) or getattr(props, "immutability_policy", None)
    if policy is None:
        return False
    state = enum_str(getattr(policy, "state", None)).lower()
    retention = getattr(policy, "immutability_period_since_creation_in_days", None)
    return state in {"locked", "unlocked"} and isinstance(retention, int) and retention > 0


def _container_evaluation(resource_id: str, status: str, **kwargs: Any) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=RULE_ID, resource_id=resource_id, resource_type=CONTAINER_RESOURCE_TYPE, status=status, **kwargs
    )


def _finding(resource_id: str, account_name: str, name: str) -> Dict[str, Any]:
    return {
        "rule_id": RULE_ID,
        "rule_name": RULE_NAME,
        "severity": SEVERITY,
        "category": CATEGORY,
        "resource_id": f"{resource_id}/blobServices/default/containers/{name}",
        "resource_name": f"{account_name}/{name}",
        "resource_type": "Microsoft.Storage/storageAccounts/blobServices/containers",
        "description": DESCRIPTION,
        "remediation": REMEDIATION,
        "playbook": PLAYBOOK,
        "frameworks": FRAMEWORKS,
        "metadata": {"requirement_tag": "oshield:immutability-required"},
    }


def _immutability_evidence(container: Any) -> Dict[str, Any]:
    props = _container_properties(container)
    policy = getattr(container, "immutability_policy", None) or getattr(props, "immutability_policy", None)
    if policy is None:
        return {"immutability_policy": None}
    return {
        "state": enum_str(getattr(policy, "state", None)),
        "retention_days": getattr(policy, "immutability_period_since_creation_in_days", None),
    }


def _evaluate_account(azure_client: Any, account: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Evaluate every blob container of an account against the opt-in policy.

    The requirement tag may sit on the account (all containers) or on a
    single container. Containers neither requires are NOT_APPLICABLE.
    """
    resource_id = getattr(account, "id", "")
    account_name = getattr(account, "name", "")
    parsed = azure_client.parse_resource_id(resource_id)
    resource_group = parsed.get("resource_group", "")
    if not resource_group or not account_name:
        return [
            _evaluation(
                resource_id or subscription_scope_id(subscription_id),
                EvaluationStatus.UNKNOWN,
                reason_code=MISSING_PROPERTIES,
                reason="Storage account was returned without a resource group or name.",
            )
        ]
    containers = azure_client.get_blob_containers(resource_group, account_name)
    if containers is None:
        logger.warning("%s: blob containers unavailable for %s; reporting UNKNOWN", RULE_ID, account_name)
        return [
            _evaluation(
                resource_id,
                EvaluationStatus.UNKNOWN,
                reason_code=EVIDENCE_UNAVAILABLE,
                reason="Blob containers could not be listed for the storage account.",
            )
        ]
    if not containers:
        return [
            _evaluation(
                resource_id,
                EvaluationStatus.NOT_APPLICABLE,
                reason_code=NO_RESOURCES_FOUND,
                reason="The storage account has no blob containers.",
            )
        ]

    account_exemption = policy_exemption(account, _REQUIREMENT_TAG)
    evaluations: List[RuleEvaluation] = []
    for container in containers:
        name = getattr(container, "name", "")
        container_id = f"{resource_id}/blobServices/default/containers/{name}"
        container_exemption = policy_exemption(container, _REQUIREMENT_TAG)
        if account_exemption and container_exemption:
            exemption = (
                APPROVED_EXCEPTION
                if APPROVED_EXCEPTION in {account_exemption, container_exemption}
                else POLICY_NOT_REQUIRED
            )
            evaluations.append(
                _container_evaluation(
                    container_id,
                    EvaluationStatus.NOT_APPLICABLE,
                    reason_code=exemption,
                    reason=f"Immutability is not required by the {_REQUIREMENT_TAG} tag.",
                )
            )
            continue
        evidence = _immutability_evidence(container)
        if _has_immutability(container):
            evaluations.append(_container_evaluation(container_id, EvaluationStatus.PASS, evidence=evidence))
        else:
            finding = _finding(resource_id, account_name, name)
            evaluations.append(
                _container_evaluation(container_id, EvaluationStatus.FAIL, evidence=evidence, finding=finding)
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
