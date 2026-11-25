"""Shared evaluate() flows for the supply-chain rules (AZ-SC-001..008).

Three inventories back these rules:

  * Container registries (AZ-SC-001..004): ``get_container_registries()``
    returns ``None`` on failure, so a failed list is ERROR and an empty one
    NOT_APPLICABLE.
  * Storage accounts and their blob containers (AZ-SC-005, 006):
    ``list_storage_accounts()`` returns ``None`` on failure; a container list
    that fails for one account is UNKNOWN for that account only.
  * Azure DevOps service connections (AZ-SC-007, 008):
    ``list_devops_service_endpoints()`` raises ``IntegrationNotConfigured``
    when Azure DevOps is not configured (NOT_APPLICABLE /
    INTEGRATION_NOT_CONFIGURED) and returns ``None`` when it is configured but
    unreachable (ERROR / INVENTORY_UNAVAILABLE).
"""

from typing import Any, Callable, Dict, List

from scanner.devops_client import IntegrationNotConfigured
from scanner.evaluation import (
    INTEGRATION_NOT_CONFIGURED,
    MISSING_PROPERTIES,
    EvaluationStatus,
    RuleEvaluation,
    inventory_unavailable,
    no_resources_found,
    subscription_scope_id,
)

REGISTRY_TYPE = "Microsoft.ContainerRegistry/registries"
STORAGE_ACCOUNT_TYPE = "Microsoft.Storage/storageAccounts"
CONTAINER_TYPE = "Microsoft.Storage/storageAccounts/blobServices/containers"
SERVICE_ENDPOINT_TYPE = "AzureDevOps/ServiceEndpoint"


def evaluation(rule_id: str, resource_id: str, resource_type: str, status: str, **kwargs: Any) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id, resource_id=resource_id, resource_type=resource_type, status=status, **kwargs
    )


def missing(rule_id: str, resource_id: str, resource_type: str, reason: str) -> RuleEvaluation:
    return evaluation(
        rule_id, resource_id, resource_type, EvaluationStatus.UNKNOWN, reason_code=MISSING_PROPERTIES, reason=reason
    )


def failed(rule_id: str, finding: Dict[str, Any], evidence: Dict[str, Any]) -> RuleEvaluation:
    """FAIL carrying ``finding``; the evaluation's resource matches the finding's."""
    return evaluation(
        rule_id,
        finding["resource_id"],
        finding["resource_type"],
        EvaluationStatus.FAIL,
        evidence=evidence,
        finding=finding,
    )


def _collection_id(subscription_id: str, provider_path: str) -> str:
    """A stable, non-empty row ID for items the API returned without their own ID."""
    return f"{subscription_scope_id(subscription_id)}/providers/{provider_path}"


def evaluate_registries(
    rule_id: str,
    azure_client: Any,
    subscription_id: str,
    judge: Callable[[Any, Any], RuleEvaluation],
) -> List[RuleEvaluation]:
    """Evaluate every container registry; ``judge(registry, properties)`` decides one registry."""
    registries = azure_client.get_container_registries()
    if registries is None:
        return [inventory_unavailable(rule_id, REGISTRY_TYPE, subscription_id)]
    if not registries:
        return [no_resources_found(rule_id, REGISTRY_TYPE, subscription_id)]

    evaluations: List[RuleEvaluation] = []
    unidentified = 0
    for registry in registries:
        if not getattr(registry, "id", None):
            unidentified += 1
            continue
        props = getattr(registry, "properties", None)
        if props is None:
            evaluations.append(
                missing(rule_id, registry.id, REGISTRY_TYPE, "The registry was returned without its properties.")
            )
            continue
        evaluations.append(judge(registry, props))
    if unidentified:
        evaluations.append(
            missing(
                rule_id,
                _collection_id(subscription_id, "Microsoft.ContainerRegistry/registries"),
                REGISTRY_TYPE,
                f"{unidentified} registr{'y was' if unidentified == 1 else 'ies were'} returned without a resource ID.",
            )
        )
    return evaluations


def evaluate_storage_accounts(
    rule_id: str,
    azure_client: Any,
    subscription_id: str,
    judge: Callable[[Any, str, str, str], List[RuleEvaluation]],
) -> List[RuleEvaluation]:
    """Evaluate every storage account; ``judge(account, account_id, name, resource_group)`` decides one."""
    accounts = azure_client.list_storage_accounts()
    if accounts is None:
        return [inventory_unavailable(rule_id, STORAGE_ACCOUNT_TYPE, subscription_id)]
    if not accounts:
        return [no_resources_found(rule_id, STORAGE_ACCOUNT_TYPE, subscription_id)]

    evaluations: List[RuleEvaluation] = []
    unidentified = 0
    for account in accounts:
        account_id = getattr(account, "id", "") or ""
        account_name = getattr(account, "name", "") or ""
        if not account_id:
            unidentified += 1
            continue
        resource_group = azure_client.parse_resource_id(account_id).get("resource_group", "")
        if not account_name or not resource_group:
            evaluations.append(
                missing(
                    rule_id,
                    account_id,
                    STORAGE_ACCOUNT_TYPE,
                    "The storage account was returned without a name or resource group.",
                )
            )
            continue
        evaluations.extend(judge(account, account_id, account_name, resource_group))
    if unidentified:
        evaluations.append(
            missing(
                rule_id,
                _collection_id(subscription_id, "Microsoft.Storage/storageAccounts"),
                STORAGE_ACCOUNT_TYPE,
                f"{unidentified} storage account(s) were returned without a resource ID.",
            )
        )
    return evaluations


def evaluate_service_endpoints(
    rule_id: str,
    azure_client: Any,
    subscription_id: str,
    judge: Callable[[Any, str], RuleEvaluation],
) -> List[RuleEvaluation]:
    """Evaluate every AzureRM service connection; ``judge(endpoint, resource_id)`` decides one.

    Other connection types (GitHub, Docker registry, ...) are outside these
    rules' scope and are not reported.
    """
    try:
        endpoints = azure_client.list_devops_service_endpoints()
    except IntegrationNotConfigured:
        return [
            evaluation(
                rule_id,
                subscription_scope_id(subscription_id),
                SERVICE_ENDPOINT_TYPE,
                EvaluationStatus.NOT_APPLICABLE,
                reason_code=INTEGRATION_NOT_CONFIGURED,
                reason="Azure DevOps is not configured (AZURE_DEVOPS_ORG_URL and AZURE_DEVOPS_PROJECT).",
            )
        ]
    if endpoints is None:
        return [inventory_unavailable(rule_id, SERVICE_ENDPOINT_TYPE, subscription_id)]

    azurerm = [e for e in endpoints if str(getattr(e, "type", "") or "").lower() == "azurerm"]
    if not azurerm:
        return [no_resources_found(rule_id, SERVICE_ENDPOINT_TYPE, subscription_id)]

    evaluations: List[RuleEvaluation] = []
    unidentified = 0
    for endpoint in azurerm:
        endpoint_id = getattr(endpoint, "id", "") or ""
        if not endpoint_id:
            unidentified += 1
            continue
        evaluations.append(judge(endpoint, f"azuredevops:serviceendpoint/{endpoint_id}"))
    if unidentified:
        evaluations.append(
            missing(
                rule_id,
                "azuredevops:serviceendpoint",
                SERVICE_ENDPOINT_TYPE,
                f"{unidentified} AzureRM service connection(s) were returned without an ID.",
            )
        )
    return evaluations
