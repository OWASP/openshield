"""Shared evaluation helpers for AZ-GOV-001 through AZ-GOV-010."""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Mapping

from scanner.governance import GovernanceCollector, GovernancePolicy, load_governance_policy

logger = logging.getLogger(__name__)
POLICY_ENV = "OPENSHIELD_GOVERNANCE_POLICY"
OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"


def value(item: Any, field: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(field, default)
    return getattr(item, field, default)


def normal(value_: Any) -> str:
    return str(value_ or "").strip().lower().rstrip("/")


def properties(item: Any) -> Mapping[str, Any]:
    candidate = value(item, "properties", {})
    return candidate if isinstance(candidate, Mapping) else {}


def load_context(azure_client: Any, subscription_id: str, rule_id: str) -> tuple[GovernancePolicy, dict] | None:
    path = os.environ.get(POLICY_ENV)
    if not path:
        logger.warning("%s: %s is unset; result is UNKNOWN", rule_id, POLICY_ENV)
        return None
    try:
        policy = load_governance_policy(path)
    except (OSError, ValueError) as exc:
        logger.warning("%s: governance policy is invalid or unavailable: %s", rule_id, exc)
        return None
    cache = getattr(azure_client, "_governance_snapshot_cache", None)
    if cache is None:
        cache = GovernanceCollector(azure_client.credential, subscription_id).collect()
        setattr(azure_client, "_governance_snapshot_cache", cache)
    return policy, cache


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


def _unknown(rule_id: str, source: str) -> list[dict]:
    logger.warning("%s: %s evidence is unavailable; result is UNKNOWN", rule_id, source)
    return []


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


def evaluate(spec: Mapping[str, Any], azure_client: Any, subscription_id: str) -> list[dict]:
    context = load_context(azure_client, subscription_id, spec["id"])
    if context is None:
        return []
    policy, snapshot = context
    rule_id = spec["id"]
    subscription_scope = f"/subscriptions/{subscription_id}"

    if rule_id == "AZ-GOV-001":
        rows = snapshot.get("hierarchy")
        if rows is None:
            return _unknown(rule_id, "management-group hierarchy")
        if not rows:
            return _unknown(rule_id, "subscription hierarchy row")
        actual: set[str] = set()
        for row in rows:
            chain = value(
                row, "managementGroupAncestorsChain", value(row, "properties_managementGroupAncestorsChain", [])
            )
            if not chain:
                chain = properties(row).get("managementGroupAncestorsChain", [])
            for ancestor in chain if isinstance(chain, list) else []:
                actual.add(normal(value(ancestor, "id", value(ancestor, "name"))))
        if actual & policy.approved_management_group_ids:
            return []
        return [
            finding(
                spec,
                subscription_id,
                subscription_scope,
                "Microsoft.Resources/subscriptions",
                {"observed_management_groups": sorted(actual)},
            )
        ]

    if rule_id in {"AZ-GOV-002", "AZ-GOV-003"}:
        assignments = snapshot.get("policy_assignments")
        if assignments is None:
            return _unknown(rule_id, "policy assignment")
        if rule_id == "AZ-GOV-002":
            found = {
                (normal(properties(item).get("policyDefinitionId")), _assignment_scope(item)) for item in assignments
            }
            missing = [
                dict(item)
                for item in policy.required_policy_initiatives
                if (item["definition_id"], item["scope"]) not in found
            ]
            return (
                []
                if not missing
                else [
                    finding(
                        spec,
                        subscription_id,
                        subscription_scope,
                        "Microsoft.Authorization/policyAssignments",
                        {"missing_assignments": missing},
                    )
                ]
            )
        definitions = snapshot.get("policy_definitions")
        if definitions is None:
            return _unknown(rule_id, "policy definition")
        definitions_by_id = {}
        for definition in definitions:
            props = properties(definition)
            definitions_by_id[normal(value(definition, "id"))] = props
        violations = []
        for item in assignments:
            props = properties(item)
            definition_id = normal(props.get("policyDefinitionId"))
            if definition_id not in policy.preventive_policy_definition_ids:
                continue
            definition = definitions_by_id.get(definition_id)
            if definition is None:
                logger.warning("%s: policy definition is unavailable for %s; result is UNKNOWN", rule_id, definition_id)
                continue
            effect = _effective_policy_effect(definition, props)
            enforcement_mode = normal(props.get("enforcementMode", "Default"))
            if not effect:
                logger.warning(
                    "%s: effective policy effect is unavailable for %s; result is UNKNOWN", rule_id, definition_id
                )
                continue
            if effect not in policy.allowed_preventive_effects or enforcement_mode == "donotenforce":
                assignment_scope = _assignment_scope(item)
                violations.append(
                    {
                        "assignment_id": value(item, "id"),
                        "assignment_scope": assignment_scope,
                        "inherited_assignment": assignment_scope != normal(subscription_scope),
                        "effect": effect,
                        "enforcement_mode": enforcement_mode,
                    }
                )
        return [
            finding(spec, subscription_id, item["assignment_id"], "Microsoft.Authorization/policyAssignments", item)
            for item in violations
        ]

    if rule_id == "AZ-GOV-004":
        exemptions = snapshot.get("policy_exemptions")
        if exemptions is None:
            return _unknown(rule_id, "policy exemption")
        if not exemptions:
            logger.info("%s: no policy exemptions exist; result is NOT_APPLICABLE", rule_id)
            return []
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
            if missing:
                resource_id = str(value(item, "id", subscription_scope))
                results.append(
                    finding(
                        spec,
                        subscription_id,
                        resource_id,
                        "Microsoft.Authorization/policyExemptions",
                        {"missing_or_invalid": missing},
                    )
                )
        return results

    if rule_id in {"AZ-GOV-005", "AZ-GOV-009"}:
        resources = snapshot.get("resources")
        if resources is None:
            return _unknown(rule_id, "resource inventory")
        production = [
            item
            for item in resources
            if _production(item, policy) and normal(value(item, "id")) not in policy.excluded_resource_ids
        ]
        if not production:
            logger.info("%s: no in-scope production resources exist; result is NOT_APPLICABLE", rule_id)
            return []
        if rule_id == "AZ-GOV-009":
            results = []
            for item in production:
                tags = value(item, "tags", {})
                tag_keys = {normal(key) for key in tags} if isinstance(tags, Mapping) else set()
                if not tag_keys & policy.ownership_tags:
                    resource_id = str(value(item, "id"))
                    results.append(
                        finding(
                            spec,
                            subscription_id,
                            resource_id,
                            str(value(item, "type")),
                            {"required_ownership_tags": sorted(policy.ownership_tags)},
                        )
                    )
            return results
        locks = snapshot.get("locks")
        if locks is None:
            return _unknown(rule_id, "resource lock")
        protected_scopes = set()
        for lock in locks:
            if normal(properties(lock).get("level")) in {"cannotdelete", "readonly"}:
                lock_id = normal(value(lock, "id"))
                protected_scopes.add(lock_id.split("/providers/microsoft.authorization/locks/", 1)[0])
        results = []
        for item in production:
            resource_id = str(value(item, "id"))
            normal_id = normal(resource_id)
            if not any(normal_id == scope or normal_id.startswith(f"{scope}/") for scope in protected_scopes):
                results.append(
                    finding(
                        spec, subscription_id, resource_id, str(value(item, "type")), {"approved_lock_found": False}
                    )
                )
        return results

    if rule_id in {"AZ-GOV-006", "AZ-GOV-007"}:
        assignments = snapshot.get("role_assignments")
        if assignments is None:
            return _unknown(rule_id, "role assignment")
        if rule_id == "AZ-GOV-006":
            # The collector uses atScope() which already returns both direct and
            # inherited (management-group) assignments effective at this subscription.
            # Count all of them; filtering to subscription scope would miss the most
            # common enterprise pattern of an Owner granted at a parent MG.
            owners = [
                item for item in assignments if normal(properties(item).get("roleDefinitionId")).endswith(OWNER_ROLE_ID)
            ]
            if len(owners) <= policy.maximum_subscription_owners:
                return []
            return [
                finding(
                    spec,
                    subscription_id,
                    subscription_scope,
                    "Microsoft.Authorization/roleAssignments",
                    {"owner_count": len(owners), "maximum": policy.maximum_subscription_owners},
                )
            ]
        results = []
        for item in assignments:
            role_id = normal(properties(item).get("roleDefinitionId"))
            scope = _assignment_scope(item)
            if (
                any(role_id.endswith(identifier) for identifier in policy.privileged_role_definition_ids)
                and scope not in policy.approved_privileged_scopes
            ):
                resource_id = str(value(item, "id", subscription_scope))
                results.append(
                    finding(
                        spec,
                        subscription_id,
                        resource_id,
                        "Microsoft.Authorization/roleAssignments",
                        {
                            "assignment_scope": scope,
                            "inherited_assignment": scope != normal(subscription_scope),
                            "role_definition_id": role_id,
                        },
                    )
                )
        return results

    if rule_id == "AZ-GOV-008":
        providers = snapshot.get("providers")
        if providers is None:
            return _unknown(rule_id, "resource provider")
        return [
            finding(
                spec,
                subscription_id,
                f"{subscription_scope}/providers/{value(item, 'namespace')}",
                "Microsoft.Resources/providers",
                {"registration_state": value(item, "registrationState")},
            )
            for item in providers
            if normal(value(item, "registrationState")) == "registered"
            and normal(value(item, "namespace")) not in policy.approved_provider_namespaces
        ]

    states = snapshot.get("policy_states")
    if states is None:
        return _unknown(rule_id, "policy state")
    results = []
    now = datetime.now(timezone.utc)
    for item in states:
        props = properties(item) or item
        if normal(props.get("complianceState")) != "noncompliant":
            continue
        timestamp = props.get("timestamp")
        try:
            observed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            logger.warning("%s: malformed policy-state timestamp; result is UNKNOWN for one resource", rule_id)
            continue
        age_days = (now.date() - observed.date()).days
        if age_days > policy.drift_sla_days:
            resource_id = str(props.get("resourceId") or subscription_scope)
            results.append(
                finding(
                    spec,
                    subscription_id,
                    resource_id,
                    str(props.get("resourceType") or "Microsoft.PolicyInsights/policyStates"),
                    {
                        "age_days": age_days,
                        "sla_days": policy.drift_sla_days,
                        "policy_assignment_id": props.get("policyAssignmentId"),
                    },
                )
            )
    return results
