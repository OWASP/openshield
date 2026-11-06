"""Shared evaluation helpers for AZ-GOV-001 through AZ-GOV-010.

Each rule exposes ``evaluate(azure_client, subscription_id)`` and delegates to
``evaluate()`` here, which reports per-rule coverage as ``RuleEvaluation``
objects (PASS included) rather than only findings. ``scan()`` stays a thin
wrapper over the FAIL evaluations' findings.

Coverage mapping, fail-closed by design:

    collector unavailable          ERROR (whole snapshot is None)
    rule's evidence set is None     ERROR (that control-plane call failed)
    governance policy unset/invalid ERROR (cannot judge, with evidence present)
    nothing in scope to evaluate    NOT_APPLICABLE
    in scope and compliant          PASS
    in scope and violating          FAIL (carries the rule finding)
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Mapping

from scanner.evaluation import (
    EVIDENCE_UNAVAILABLE,
    INVENTORY_UNAVAILABLE,
    POLICY_UNAVAILABLE,
    EvaluationStatus,
    RuleEvaluation,
    no_resources_found,
    subscription_scope_id,
)
from scanner.governance import GovernanceCollector, GovernancePolicy, load_governance_policy

logger = logging.getLogger(__name__)
POLICY_ENV = "OPENSHIELD_GOVERNANCE_POLICY"
OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

# Resource type reported for subscription-scope evaluations (ERROR, PASS and
# NOT_APPLICABLE) of each rule. FAIL evaluations use the type on the finding.
_RESOURCE_TYPE = {
    "AZ-GOV-001": "Microsoft.Resources/subscriptions",
    "AZ-GOV-002": "Microsoft.Authorization/policyAssignments",
    "AZ-GOV-003": "Microsoft.Authorization/policyAssignments",
    "AZ-GOV-004": "Microsoft.Authorization/policyExemptions",
    "AZ-GOV-005": "Microsoft.Resources/resources",
    "AZ-GOV-006": "Microsoft.Authorization/roleAssignments",
    "AZ-GOV-007": "Microsoft.Authorization/roleAssignments",
    "AZ-GOV-008": "Microsoft.Resources/providers",
    "AZ-GOV-009": "Microsoft.Resources/resources",
    "AZ-GOV-010": "Microsoft.PolicyInsights/policyStates",
}


def value(item: Any, field: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(field, default)
    return getattr(item, field, default)


def normal(value_: Any) -> str:
    return str(value_ or "").strip().lower().rstrip("/")


def properties(item: Any) -> Mapping[str, Any]:
    candidate = value(item, "properties", {})
    return candidate if isinstance(candidate, Mapping) else {}


def _resolve_policy(rule_id: str) -> GovernancePolicy | None:
    path = os.environ.get(POLICY_ENV)
    if not path:
        logger.warning("%s: %s is unset; result is ERROR", rule_id, POLICY_ENV)
        return None
    try:
        return load_governance_policy(path)
    except (OSError, ValueError) as exc:
        logger.warning("%s: governance policy is invalid or unavailable: %s", rule_id, exc)
        return None


def _resolve_snapshot(azure_client: Any, subscription_id: str) -> dict | None:
    """Collect the governance snapshot once per subscription and cache it on the client.

    Prefers ``azure_client.get_governance_snapshot(subscription_id)`` so the
    snapshot is interceptable by test clients and the engine's real
    ``AzureClient`` alike; falls back to the collector directly for callers
    that only supply a credential. The subscription-keyed cache prevents a
    stale snapshot from one subscription being replayed against another.
    """
    cache = getattr(azure_client, "_governance_snapshot_cache", None)
    cache_sub = getattr(azure_client, "_governance_snapshot_cache_sub", None)
    if cache is not None and cache_sub == subscription_id:
        return cache
    snapshot_source = getattr(azure_client, "get_governance_snapshot", None)
    if callable(snapshot_source):
        snapshot = snapshot_source(subscription_id)
    else:
        snapshot = GovernanceCollector(azure_client.credential, subscription_id).collect()
    setattr(azure_client, "_governance_snapshot_cache", snapshot)
    setattr(azure_client, "_governance_snapshot_cache_sub", subscription_id)
    return snapshot


def load_context(azure_client: Any, subscription_id: str, rule_id: str) -> tuple[GovernancePolicy | None, dict | None]:
    """Resolve the governance policy and the collected snapshot for a scan.

    Returns a ``(policy, snapshot)`` pair. ``policy`` is ``None`` when the
    policy env var is unset or the file is invalid; ``snapshot`` is ``None``
    when the collection could not run at all. ``evaluate()`` turns each of
    those into the appropriate fail-closed coverage status.
    """
    policy = _resolve_policy(rule_id)
    snapshot = _resolve_snapshot(azure_client, subscription_id)
    return policy, snapshot


def _resource_name(resource_id: str) -> str:
    return PurePosixPath(resource_id).name or "subscription"


def finding(
    spec: Mapping[str, Any], subscription_id: str, resource_id: str, resource_type: str, evidence: dict
) -> dict:
    return {
        "rule_id": spec["id"],
        "rule_name": spec["name"],
        "severity": spec["severity"],
        "category": "Governance",
        "resource_id": resource_id,
        "resource_name": _resource_name(resource_id),
        "resource_type": resource_type,
        "description": spec["description"],
        "remediation": spec["remediation"],
        "playbook": spec["playbook"],
        "frameworks": spec["frameworks"],
        "metadata": {
            "scope": resource_id or f"/subscriptions/{subscription_id}",
            "effective_scope": evidence.get("assignment_scope", resource_id),
            "inherited_assignment": evidence.get("inherited_assignment", False),
            "exception_state": evidence.get("exception_state", "not_exempt"),
            "unknown_reason": None,
            "evidence": evidence,
            "confidence": "HIGH",
            "permissions_required": spec["permissions"],
            "evidence_collected_at": datetime.now(timezone.utc).isoformat(),
        },
    }


# ── RuleEvaluation constructors ─────────────────────────────────────────────


def _passing(rule_id: str, resource_type: str, subscription_id: str, evidence: dict) -> RuleEvaluation:
    """Subscription-scope PASS for an aggregate rule that found no violation."""
    return RuleEvaluation(
        rule_id=rule_id,
        resource_id=subscription_scope_id(subscription_id),
        resource_type=resource_type,
        status=EvaluationStatus.PASS,
        evidence=evidence,
    )


def _passing_resource(rule_id: str, resource_id: str, resource_type: str, evidence: dict) -> RuleEvaluation:
    """Per-resource PASS for a rule that evaluates each resource individually."""
    return RuleEvaluation(
        rule_id=rule_id,
        resource_id=resource_id,
        resource_type=resource_type,
        status=EvaluationStatus.PASS,
        evidence=evidence,
    )


def _fail(rule_id: str, finding_dict: dict) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        resource_id=finding_dict["resource_id"],
        resource_type=finding_dict["resource_type"],
        status=EvaluationStatus.FAIL,
        finding=finding_dict,
    )


def _evidence_error(rule_id: str, resource_type: str, subscription_id: str, source: str) -> RuleEvaluation:
    logger.warning("%s: %s evidence is unavailable; result is ERROR", rule_id, source)
    return RuleEvaluation(
        rule_id=rule_id,
        resource_id=subscription_scope_id(subscription_id),
        resource_type=resource_type,
        status=EvaluationStatus.ERROR,
        reason_code=INVENTORY_UNAVAILABLE,
        reason=f"The {source} evidence could not be read for this subscription.",
    )


def _policy_error(rule_id: str, resource_type: str, subscription_id: str) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        resource_id=subscription_scope_id(subscription_id),
        resource_type=resource_type,
        status=EvaluationStatus.ERROR,
        reason_code=POLICY_UNAVAILABLE,
        reason=f"{POLICY_ENV} is unset or invalid; governance compliance cannot be judged.",
    )


def _unknown_resource(rule_id: str, resource_id: str, resource_type: str, reason: str) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        resource_id=resource_id,
        resource_type=resource_type,
        status=EvaluationStatus.UNKNOWN,
        reason_code=EVIDENCE_UNAVAILABLE,
        reason=reason,
    )


# ── Policy-effect helpers (unchanged) ───────────────────────────────────────


def _production(resource: Mapping[str, Any], policy: GovernancePolicy) -> bool:
    if normal(value(resource, "type")) not in policy.production_resource_types:
        return False
    tags = value(resource, "tags", {})
    if not isinstance(tags, Mapping):
        return False
    lowered = {normal(key): normal(item) for key, item in tags.items()}
    return lowered.get(policy.production_tag) in policy.production_tag_values


def _assignment_scope(assignment: Mapping[str, Any]) -> str:
    resource_id = normal(value(assignment, "id"))
    marker = "/providers/microsoft.authorization/"
    return resource_id.split(marker, 1)[0] if marker in resource_id else resource_id


def _effective_policy_effect(definition: Mapping[str, Any], assignment: Mapping[str, Any]) -> str:
    policy_rule = definition.get("policyRule", {})
    then = policy_rule.get("then", {}) if isinstance(policy_rule, Mapping) else {}
    raw_effect = value(then, "effect")
    if not isinstance(raw_effect, str):
        return ""
    parameter_match = re.fullmatch(r"\[parameters\(['\"]([^'\"]+)['\"]\)\]", raw_effect.strip(), re.IGNORECASE)
    if not parameter_match:
        return normal(raw_effect)
    parameter_name = normal(parameter_match.group(1))
    assigned = assignment.get("parameters", {})
    if isinstance(assigned, Mapping):
        for key, parameter in assigned.items():
            if normal(key) == parameter_name:
                return normal(value(parameter, "value", parameter))
    declared = definition.get("parameters", {})
    if isinstance(declared, Mapping):
        for key, parameter in declared.items():
            if normal(key) == parameter_name:
                return normal(value(parameter, "defaultValue"))
    return ""


# ── Per-rule evaluators ─────────────────────────────────────────────────────


def _eval_001(spec, policy, snapshot, subscription_id, resource_type):
    rule_id = spec["id"]
    scope = subscription_scope_id(subscription_id)
    rows = snapshot.get("hierarchy")
    if rows is None:
        return [_evidence_error(rule_id, resource_type, subscription_id, "management-group hierarchy")]
    if not rows:
        return [no_resources_found(rule_id, resource_type, subscription_id)]
    actual: set[str] = set()
    for row in rows:
        chain = value(row, "managementGroupAncestorsChain", value(row, "properties_managementGroupAncestorsChain", []))
        if not chain:
            chain = properties(row).get("managementGroupAncestorsChain", [])
        for ancestor in chain if isinstance(chain, list) else []:
            actual.add(normal(value(ancestor, "id", value(ancestor, "name"))))
    evidence = {"observed_management_groups": sorted(actual)}
    if actual & policy.approved_management_group_ids:
        return [_passing(rule_id, resource_type, subscription_id, evidence)]
    return [_fail(rule_id, finding(spec, subscription_id, scope, resource_type, evidence))]


def _eval_002(spec, policy, snapshot, subscription_id, resource_type):
    rule_id = spec["id"]
    scope = subscription_scope_id(subscription_id)
    assignments = snapshot.get("policy_assignments")
    if assignments is None:
        return [_evidence_error(rule_id, resource_type, subscription_id, "policy assignment")]
    found = {(normal(properties(item).get("policyDefinitionId")), _assignment_scope(item)) for item in assignments}
    missing = [
        dict(item) for item in policy.required_policy_initiatives if (item["definition_id"], item["scope"]) not in found
    ]
    if not missing:
        return [_passing(rule_id, resource_type, subscription_id, {"missing_assignments": []})]
    return [_fail(rule_id, finding(spec, subscription_id, scope, resource_type, {"missing_assignments": missing}))]


def _eval_003(spec, policy, snapshot, subscription_id, resource_type):
    rule_id = spec["id"]
    scope = subscription_scope_id(subscription_id)
    assignments = snapshot.get("policy_assignments")
    if assignments is None:
        return [_evidence_error(rule_id, resource_type, subscription_id, "policy assignment")]
    definitions = snapshot.get("policy_definitions")
    if definitions is None:
        return [_evidence_error(rule_id, resource_type, subscription_id, "policy definition")]
    definitions_by_id = {normal(value(definition, "id")): properties(definition) for definition in definitions}
    violations = []
    evidence_gaps = 0
    for item in assignments:
        props = properties(item)
        definition_id = normal(props.get("policyDefinitionId"))
        if definition_id not in policy.preventive_policy_definition_ids:
            continue
        definition = definitions_by_id.get(definition_id)
        if definition is None:
            logger.warning("%s: policy definition is unavailable for %s; result is UNKNOWN", rule_id, definition_id)
            evidence_gaps += 1
            continue
        effect = _effective_policy_effect(definition, props)
        enforcement_mode = normal(props.get("enforcementMode", "Default"))
        if not effect:
            logger.warning(
                "%s: effective policy effect is unavailable for %s; result is UNKNOWN", rule_id, definition_id
            )
            evidence_gaps += 1
            continue
        if effect not in policy.allowed_preventive_effects or enforcement_mode == "donotenforce":
            assignment_scope = _assignment_scope(item)
            violations.append(
                {
                    "assignment_id": value(item, "id"),
                    "assignment_scope": assignment_scope,
                    "inherited_assignment": assignment_scope != normal(scope),
                    "effect": effect,
                    "enforcement_mode": enforcement_mode,
                }
            )
    if violations:
        return [
            _fail(rule_id, finding(spec, subscription_id, item["assignment_id"], resource_type, item))
            for item in violations
        ]
    if evidence_gaps:
        return [_unknown_resource(rule_id, scope, resource_type, "preventive policy effect evidence was unavailable")]
    return [_passing(rule_id, resource_type, subscription_id, {"preventive_policies_enforced": True})]


def _eval_004(spec, policy, snapshot, subscription_id, resource_type):
    rule_id = spec["id"]
    scope = subscription_scope_id(subscription_id)
    exemptions = snapshot.get("policy_exemptions")
    if exemptions is None:
        return [_evidence_error(rule_id, resource_type, subscription_id, "policy exemption")]
    if not exemptions:
        logger.info("%s: no policy exemptions exist; result is NOT_APPLICABLE", rule_id)
        return [no_resources_found(rule_id, resource_type, subscription_id)]
    results = []
    now = datetime.now(timezone.utc)
    for item in exemptions:
        props = properties(item)
        expires = props.get("expiresOn")
        expired = False
        if isinstance(expires, str):
            try:
                parsed_expiration = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                expired = parsed_expiration.tzinfo is None or parsed_expiration <= now
            except (TypeError, ValueError):
                expired = True
        metadata = props.get("metadata", {}) if isinstance(props.get("metadata", {}), Mapping) else {}
        missing = []
        if not normal(metadata.get("owner")):
            missing.append("owner")
        if not normal(metadata.get("justification", props.get("description"))):
            missing.append("justification")
        if not expires or expired:
            missing.append("valid expiration")
        resource_id = str(value(item, "id", scope))
        if missing:
            results.append(
                _fail(
                    rule_id, finding(spec, subscription_id, resource_id, resource_type, {"missing_or_invalid": missing})
                )
            )
        else:
            results.append(_passing_resource(rule_id, resource_id, resource_type, {"missing_or_invalid": []}))
    return results


def _production_in_scope(policy, snapshot):
    resources = snapshot.get("resources")
    if resources is None:
        return None
    return [
        item
        for item in resources
        if _production(item, policy) and normal(value(item, "id")) not in policy.excluded_resource_ids
    ]


def _eval_005(spec, policy, snapshot, subscription_id, resource_type):
    rule_id = spec["id"]
    production = _production_in_scope(policy, snapshot)
    if production is None:
        return [_evidence_error(rule_id, resource_type, subscription_id, "resource inventory")]
    if not production:
        logger.info("%s: no in-scope production resources exist; result is NOT_APPLICABLE", rule_id)
        return [no_resources_found(rule_id, resource_type, subscription_id)]
    locks = snapshot.get("locks")
    if locks is None:
        return [_evidence_error(rule_id, resource_type, subscription_id, "resource lock")]
    protected_scopes = set()
    for lock in locks:
        if normal(properties(lock).get("level")) in {"cannotdelete", "readonly"}:
            lock_id = normal(value(lock, "id"))
            protected_scopes.add(lock_id.split("/providers/microsoft.authorization/locks/", 1)[0])
    results = []
    for item in production:
        resource_id = str(value(item, "id"))
        item_type = str(value(item, "type"))
        normal_id = normal(resource_id)
        protected = any(normal_id == scope or normal_id.startswith(f"{scope}/") for scope in protected_scopes)
        if protected:
            results.append(_passing_resource(rule_id, resource_id, item_type, {"approved_lock_found": True}))
        else:
            results.append(
                _fail(rule_id, finding(spec, subscription_id, resource_id, item_type, {"approved_lock_found": False}))
            )
    return results


def _eval_006(spec, policy, snapshot, subscription_id, resource_type):
    rule_id = spec["id"]
    scope = subscription_scope_id(subscription_id)
    assignments = snapshot.get("role_assignments")
    if assignments is None:
        return [_evidence_error(rule_id, resource_type, subscription_id, "role assignment")]
    # The collector uses atScope() which already returns both direct and
    # inherited (management-group) assignments effective at this subscription.
    owners = [
        item
        for item in assignments
        if normal(properties(item).get("roleDefinitionId", "")).rsplit("/", 1)[-1] == OWNER_ROLE_ID
    ]
    evidence = {"owner_count": len(owners), "maximum": policy.maximum_subscription_owners}
    if len(owners) <= policy.maximum_subscription_owners:
        return [_passing(rule_id, resource_type, subscription_id, evidence)]
    return [_fail(rule_id, finding(spec, subscription_id, scope, resource_type, evidence))]


def _eval_007(spec, policy, snapshot, subscription_id, resource_type):
    rule_id = spec["id"]
    scope = subscription_scope_id(subscription_id)
    assignments = snapshot.get("role_assignments")
    if assignments is None:
        return [_evidence_error(rule_id, resource_type, subscription_id, "role assignment")]
    results = []
    for item in assignments:
        role_id = normal(properties(item).get("roleDefinitionId"))
        if not any(role_id.rsplit("/", 1)[-1] == identifier for identifier in policy.privileged_role_definition_ids):
            continue
        assignment_scope = _assignment_scope(item)
        resource_id = str(value(item, "id", scope))
        evidence = {
            "assignment_scope": assignment_scope,
            "inherited_assignment": assignment_scope != normal(scope),
            "role_definition_id": role_id,
        }
        if assignment_scope not in policy.approved_privileged_scopes:
            results.append(_fail(rule_id, finding(spec, subscription_id, resource_id, resource_type, evidence)))
        else:
            results.append(_passing_resource(rule_id, resource_id, resource_type, evidence))
    if not results:
        logger.info("%s: no privileged role assignments exist; result is NOT_APPLICABLE", rule_id)
        return [no_resources_found(rule_id, resource_type, subscription_id)]
    return results


def _eval_008(spec, policy, snapshot, subscription_id, resource_type):
    rule_id = spec["id"]
    scope = subscription_scope_id(subscription_id)
    providers = snapshot.get("providers")
    if providers is None:
        return [_evidence_error(rule_id, resource_type, subscription_id, "resource provider")]
    registered = [item for item in providers if normal(value(item, "registrationState")) == "registered"]
    if not registered:
        logger.info("%s: no registered resource providers exist; result is NOT_APPLICABLE", rule_id)
        return [no_resources_found(rule_id, resource_type, subscription_id)]
    results = []
    for item in registered:
        namespace = normal(value(item, "namespace"))
        provider_id = f"{scope}/providers/{value(item, 'namespace')}"
        evidence = {"registration_state": value(item, "registrationState")}
        if namespace not in policy.approved_provider_namespaces:
            results.append(_fail(rule_id, finding(spec, subscription_id, provider_id, resource_type, evidence)))
        else:
            results.append(_passing_resource(rule_id, provider_id, resource_type, evidence))
    return results


def _eval_009(spec, policy, snapshot, subscription_id, resource_type):
    rule_id = spec["id"]
    production = _production_in_scope(policy, snapshot)
    if production is None:
        return [_evidence_error(rule_id, resource_type, subscription_id, "resource inventory")]
    if not production:
        logger.info("%s: no in-scope production resources exist; result is NOT_APPLICABLE", rule_id)
        return [no_resources_found(rule_id, resource_type, subscription_id)]
    results = []
    for item in production:
        resource_id = str(value(item, "id"))
        item_type = str(value(item, "type"))
        tags = value(item, "tags", {})
        tag_keys = {normal(key) for key in tags} if isinstance(tags, Mapping) else set()
        if tag_keys & policy.ownership_tags:
            results.append(_passing_resource(rule_id, resource_id, item_type, {"ownership_tag_present": True}))
        else:
            results.append(
                _fail(
                    rule_id,
                    finding(
                        spec,
                        subscription_id,
                        resource_id,
                        item_type,
                        {"required_ownership_tags": sorted(policy.ownership_tags)},
                    ),
                )
            )
    return results


def _eval_010(spec, policy, snapshot, subscription_id, resource_type):
    rule_id = spec["id"]
    scope = subscription_scope_id(subscription_id)
    states = snapshot.get("policy_states")
    if states is None:
        return [_evidence_error(rule_id, resource_type, subscription_id, "policy state")]
    noncompliant = [
        item for item in states if normal((properties(item) or item).get("complianceState")) == "noncompliant"
    ]
    if not noncompliant:
        logger.info("%s: no non-compliant policy states exist; result is NOT_APPLICABLE", rule_id)
        return [no_resources_found(rule_id, resource_type, subscription_id)]
    results = []
    now = datetime.now(timezone.utc)
    for item in noncompliant:
        props = properties(item) or item
        resource_id = str(props.get("resourceId") or scope)
        item_type = str(props.get("resourceType") or resource_type)
        timestamp = props.get("timestamp")
        try:
            observed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            logger.warning("%s: malformed policy-state timestamp; result is UNKNOWN for one resource", rule_id)
            results.append(_unknown_resource(rule_id, resource_id, item_type, "policy-state timestamp was malformed"))
            continue
        age_days = (now.date() - observed.date()).days
        if age_days > policy.drift_sla_days:
            results.append(
                _fail(
                    rule_id,
                    finding(
                        spec,
                        subscription_id,
                        resource_id,
                        item_type,
                        {
                            "age_days": age_days,
                            "sla_days": policy.drift_sla_days,
                            "policy_assignment_id": props.get("policyAssignmentId"),
                        },
                    ),
                )
            )
        else:
            results.append(
                _passing_resource(
                    rule_id, resource_id, item_type, {"age_days": age_days, "sla_days": policy.drift_sla_days}
                )
            )
    return results


_EVALUATORS = {
    "AZ-GOV-001": _eval_001,
    "AZ-GOV-002": _eval_002,
    "AZ-GOV-003": _eval_003,
    "AZ-GOV-004": _eval_004,
    "AZ-GOV-005": _eval_005,
    "AZ-GOV-006": _eval_006,
    "AZ-GOV-007": _eval_007,
    "AZ-GOV-008": _eval_008,
    "AZ-GOV-009": _eval_009,
    "AZ-GOV-010": _eval_010,
}


def evaluate(spec: Mapping[str, Any], azure_client: Any, subscription_id: str) -> list[RuleEvaluation]:
    """Report one AZ-GOV rule's coverage as a list of ``RuleEvaluation``."""
    rule_id = spec["id"]
    resource_type = _RESOURCE_TYPE[rule_id]
    policy, snapshot = load_context(azure_client, subscription_id, rule_id)
    if snapshot is None:
        return [_evidence_error(rule_id, resource_type, subscription_id, "governance control-plane")]
    if not snapshot:
        return [no_resources_found(rule_id, resource_type, subscription_id)]
    if policy is None:
        return [_policy_error(rule_id, resource_type, subscription_id)]
    return _EVALUATORS[rule_id](spec, policy, snapshot, subscription_id, resource_type)
