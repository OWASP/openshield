"""Shared, secret-safe helpers for the security-operations rules (AZ-SECOPS-001..010).

Every rule reports its coverage through ``evaluate()`` (the contract in
``scanner/evaluation.py``), so PASS, UNKNOWN and NOT_APPLICABLE are explicit
rows rather than an empty findings list plus a log line:

  * The collector is the rule's inventory. If it cannot be built, the rule is
    ERROR / INVENTORY_UNAVAILABLE, and so is any subscription-wide collection
    that FAILED.
  * The organisation policy is opt-in. If it is unset, missing or invalid,
    the rule is UNKNOWN / POLICY_NOT_CONFIGURED: there is nothing approved to
    judge against, and an unconfigured deployment is not a failed scan.
  * A per-resource or per-workspace gap (a lookup that failed for one scope,
    a field the API did not return) is UNKNOWN for that scope only.
  * FAIL still needs positive evidence of a missing or unsafe control, and
    carries the same finding dict ``scan()`` returned before.

The richer metadata from issue #262 (scope, destination, retention,
ownership, evidence timestamp, permissions, confidence) stays on each FAIL
finding's ``metadata``.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from scanner.evaluation import (
    APPROVED_EXCEPTION,
    EVIDENCE_UNAVAILABLE,
    INVENTORY_UNAVAILABLE,
    POLICY_NOT_CONFIGURED,
    EvaluationStatus,
    RuleEvaluation,
    inventory_unavailable,
    no_resources_found,
    subscription_scope_id,
)
from scanner.security_operations import (
    CollectionResult,
    CollectionStatus,
    SecurityOperationsCollector,
    SecurityOperationsPolicy,
    arm_resource_inventory,
    load_security_operations_policy,
)

logger = logging.getLogger(__name__)

# The policy file is organisation-owned and is never loaded by default (see
# docs/security-operations-rules.md). A rule that cannot resolve a policy
# path has no approved scope, destinations, retention, or SLA to evaluate
# against, so its only safe outcome is UNKNOWN — never PASS and never FAIL.
POLICY_PATH_ENV_VAR = "OPENSHIELD_SECURITY_OPERATIONS_POLICY"

SUBSCRIPTION_RESOURCE_TYPE = "Microsoft.Resources/subscriptions"
CRITICAL_RESOURCE_TYPE = "critical-resource"

# Kept under its original name for existing imports.
default_resource_inventory = arm_resource_inventory


def value(item: Any, field: str, default: Any = None) -> Any:
    """Read an SDK model or test dictionary field without raising."""
    if item is None:
        return default
    if isinstance(item, dict):
        return item.get(field, default)
    return getattr(item, field, default)


def enum_value(item: Any) -> str:
    """Normalise an Azure SDK enum-like value (or plain string) to a lowercase string."""
    if item is None:
        return ""
    return str(getattr(item, "value", item)).strip().lower()


def load_policy_from_env(rule_id: str) -> Optional[SecurityOperationsPolicy]:
    """Load the organisation's security-operations policy from the configured path.

    Returns ``None`` (never raises) when the environment variable is unset,
    the file is missing, or the file fails strict validation — every caller
    must treat ``None`` as UNKNOWN, not as "no policy required".
    """
    path = os.environ.get(POLICY_PATH_ENV_VAR)
    if not path:
        logger.warning(
            "%s: %s is not set; security-operations policy is unavailable, result is UNKNOWN",
            rule_id,
            POLICY_PATH_ENV_VAR,
        )
        return None
    try:
        return load_security_operations_policy(path)
    except Exception as exc:
        logger.warning("%s: failed to load security-operations policy from %s: %s", rule_id, path, exc)
        return None


def build_collector(azure_client: Any, subscription_id: str) -> Any:
    """Return the collector for this scan, or ``None`` when it cannot be built.

    ``AzureClient.get_security_operations_collector()`` is preferred, so the
    collector is reached through the client like every other inventory. A
    client without that method falls back to building one from its
    credential.
    """
    hook = getattr(azure_client, "get_security_operations_collector", None)
    if callable(hook):
        return hook(subscription_id)
    credential = getattr(azure_client, "credential", None)
    try:
        return SecurityOperationsCollector(
            credential,
            subscription_id,
            resource_inventory=default_resource_inventory(credential, subscription_id),
        )
    except Exception as exc:
        logger.error("security-operations collector could not be built: %s", exc)
        return None


def is_usable(result: CollectionResult[Any]) -> bool:
    """Return True when a CollectionResult has at least partial evidence to evaluate."""
    return result.status in (CollectionStatus.COMPLETE, CollectionStatus.PARTIAL)


def evidence_timestamp() -> str:
    """Return the evidence-collection timestamp used on every finding (UTC, ISO 8601)."""
    return datetime.now(timezone.utc).isoformat()


def is_excluded(resource_id: str, policy: SecurityOperationsPolicy) -> bool:
    """Return True when a resource ID matches an organisation-approved exclusion.

    Exclusions are matched case-insensitively against the full resource ID so
    an approved exception never produces a false FAIL finding.
    """
    normalised = str(resource_id or "").strip().lower()
    return normalised in policy.approved_exclusions


def destinations_of(setting: Any) -> List[str]:
    """Normalised export destinations of one diagnostic setting."""
    found = []
    for field in ("workspace_id", "storage_account_id", "event_hub_authorization_rule_id"):
        dest = value(setting, field)
        if dest:
            found.append(str(dest).strip().lower())
    return found


# ── evaluate() building blocks ──────────────────────────────────────────────


def prepare(
    rule_id: str,
    resource_type: str,
    azure_client: Any,
    subscription_id: str,
    build: Callable[[Any, str], Any],
) -> Tuple[Any, Optional[SecurityOperationsPolicy], Optional[List[RuleEvaluation]]]:
    """Resolve the collector and the policy, or the terminal evaluations when either is missing.

    ``build`` is the rule module's own ``build_collector`` reference, so a
    test that patches it on the module keeps working. Returns
    ``(collector, policy, None)`` when the rule can go on, else
    ``(None, None, evaluations)``.
    """
    collector = build(azure_client, subscription_id)
    if collector is None:
        return None, None, [inventory_unavailable(rule_id, resource_type, subscription_id)]
    if not collector:
        # A client that reports no security-operations evidence sources at all.
        return None, None, [no_resources_found(rule_id, resource_type, subscription_id)]
    policy = load_policy_from_env(rule_id)
    if policy is None:
        return (
            None,
            None,
            [
                RuleEvaluation(
                    rule_id=rule_id,
                    resource_id=subscription_scope_id(subscription_id),
                    resource_type=resource_type,
                    status=EvaluationStatus.UNKNOWN,
                    reason_code=POLICY_NOT_CONFIGURED,
                    reason=f"{POLICY_PATH_ENV_VAR} is unset or invalid; there is no approved policy to judge against.",
                )
            ],
        )
    return collector, policy, None


def collection_failed(
    rule_id: str, resource_type: str, subscription_id: str, result: CollectionResult[Any]
) -> RuleEvaluation:
    """ERROR for a subscription-wide collection that produced no usable evidence."""
    return RuleEvaluation(
        rule_id=rule_id,
        resource_id=subscription_scope_id(subscription_id),
        resource_type=resource_type,
        status=EvaluationStatus.ERROR,
        reason_code=INVENTORY_UNAVAILABLE,
        reason=f"{result.source} could not be collected ({result.error_code or 'COLLECTION_FAILED'}).",
    )


def scope_unknown(rule_id: str, resource_id: str, resource_type: str, reason: str) -> RuleEvaluation:
    """UNKNOWN for one scope whose evidence could not be collected."""
    return RuleEvaluation(
        rule_id=rule_id,
        resource_id=resource_id,
        resource_type=resource_type,
        status=EvaluationStatus.UNKNOWN,
        reason_code=EVIDENCE_UNAVAILABLE,
        reason=reason,
    )


def not_applicable(rule_id: str, resource_id: str, resource_type: str, reason_code: str, reason: str) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        resource_id=resource_id,
        resource_type=resource_type,
        status=EvaluationStatus.NOT_APPLICABLE,
        reason_code=reason_code,
        reason=reason,
    )


def passed(rule_id: str, resource_id: str, resource_type: str, evidence: Dict[str, Any]) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        resource_id=resource_id,
        resource_type=resource_type,
        status=EvaluationStatus.PASS,
        evidence=evidence,
    )


def failed(rule_id: str, finding: Dict[str, Any], evidence: Dict[str, Any]) -> RuleEvaluation:
    """FAIL carrying ``finding``; the evaluation's resource matches the finding's."""
    return RuleEvaluation(
        rule_id=rule_id,
        resource_id=finding["resource_id"],
        resource_type=finding["resource_type"],
        status=EvaluationStatus.FAIL,
        evidence=evidence,
        finding=finding,
    )


def workspace_resource_id(subscription_id: str, scope: str) -> str:
    """ARM ID for a Sentinel scope given either as an ID or as ``resource_group/workspace``."""
    if scope.startswith("/"):
        return scope
    resource_group, _, workspace_name = scope.partition("/")
    return (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
    )


def evaluate_critical_resources(
    rule_id: str,
    azure_client: Any,
    subscription_id: str,
    build: Callable[[Any, str], Any],
    judge: Callable[[str, Sequence[Any], SecurityOperationsPolicy], RuleEvaluation],
) -> List[RuleEvaluation]:
    """Shared flow for the per-critical-resource diagnostics rules (AZ-SECOPS-003..005).

    The critical-resource inventory is the rule's inventory: a failure is
    ERROR and an empty one NOT_APPLICABLE. Approved exclusions are
    NOT_APPLICABLE / APPROVED_EXCEPTION. If the diagnostic settings cannot be
    read, every in-scope resource is UNKNOWN. Otherwise ``judge`` decides
    each resource from its diagnostic settings.
    """
    collector, policy, early = prepare(rule_id, CRITICAL_RESOURCE_TYPE, azure_client, subscription_id, build)
    if early is not None:
        return early
    critical = collector.critical_resource_ids(policy)
    if not is_usable(critical):
        return [collection_failed(rule_id, CRITICAL_RESOURCE_TYPE, subscription_id, critical)]
    if not critical.items:
        return [no_resources_found(rule_id, CRITICAL_RESOURCE_TYPE, subscription_id)]

    evaluations: List[RuleEvaluation] = []
    in_scope: List[str] = []
    for resource_id in critical.items:
        if is_excluded(resource_id, policy):
            evaluations.append(
                not_applicable(
                    rule_id,
                    resource_id,
                    CRITICAL_RESOURCE_TYPE,
                    APPROVED_EXCEPTION,
                    "The resource is an approved exclusion in the security-operations policy.",
                )
            )
        else:
            in_scope.append(resource_id)
    if not in_scope:
        return evaluations

    diagnostics = collector.resource_diagnostic_settings(in_scope)
    if not is_usable(diagnostics) or not diagnostics.items:
        logger.warning("%s: resource diagnostic settings unavailable (%s)", rule_id, diagnostics.error_code)
        return evaluations + [
            scope_unknown(
                rule_id,
                resource_id,
                CRITICAL_RESOURCE_TYPE,
                "The resource's diagnostic settings could not be collected.",
            )
            for resource_id in in_scope
        ]
    per_resource = diagnostics.items[0]
    for resource_id in in_scope:
        evaluations.append(judge(resource_id, per_resource.get(resource_id, ()), policy))
    return evaluations


def build_finding(
    *,
    rule_id: str,
    rule_name: str,
    severity: str,
    category: str,
    resource_id: str,
    resource_name: str,
    resource_type: str,
    description: str,
    remediation: str,
    playbook: str,
    frameworks: dict,
    scope: str,
    confidence: str = "HIGH",
    metadata: Optional[dict] = None,
) -> dict:
    """Build a finding dict carrying the issue #262 required metadata fields.

    ``scope``, ``category``, ``destination``, ``retention``, ``ownership``,
    ``evidence_collected_at``, ``remediation``, ``permissions_required``,
    ``severity``, and ``confidence`` all live under ``metadata`` alongside
    the rule-specific fields the caller supplies, so nothing in the required
    field list is dropped even though the top-level finding shape must match
    every other rule in this repo (see _REQUIRED_FIELDS in
    tests/test_rules_keyvault.py).
    """
    merged_metadata = {
        "scope": scope,
        "evidence_collected_at": evidence_timestamp(),
        "confidence": confidence,
    }
    merged_metadata.update(metadata or {})
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "category": category,
        "resource_id": resource_id,
        "resource_name": resource_name,
        "resource_type": resource_type,
        "description": description,
        "remediation": remediation,
        "playbook": playbook,
        "frameworks": frameworks,
        "metadata": merged_metadata,
    }
