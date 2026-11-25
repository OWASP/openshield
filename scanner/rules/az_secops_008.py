"""AZ-SECOPS-008: A required Microsoft Sentinel data connector is disconnected or unhealthy."""

import logging
from typing import Any, Dict, List

from scanner.evaluation import (
    POLICY_NOT_REQUIRED,
    RuleEvaluation,
    fail_findings,
    no_resources_found,
    subscription_scope_id,
)
from scanner.rules._security_operations_common import (
    build_collector,
    build_finding,
    collection_failed,
    failed,
    not_applicable,
    passed,
    prepare,
    scope_unknown,
    value,
    workspace_resource_id,
)
from scanner.security_operations import CollectionStatus, workspace_scope_key

logger = logging.getLogger(__name__)

RULE_ID = "AZ-SECOPS-008"
RULE_NAME = "Required Microsoft Sentinel Data Connector Disconnected or Unhealthy"
SEVERITY = "HIGH"
CATEGORY = "Security Operations"
FRAMEWORKS = {"CIS": "N/A-SECOPS-008", "NIST": "DE.AE-3", "ISO27001": "A.8.16", "SOC2": "CC7.2"}
DESCRIPTION = (
    "An organisation-required Microsoft Sentinel data connector is either missing from a "
    "Sentinel-onboarded workspace or present with every one of its log data types disabled, which "
    "Azure surfaces as the connector showing 'Not connected' in the Sentinel portal. Sentinel "
    "workspace scope is auto-discovered: every Log Analytics workspace in the subscription is "
    "checked for Sentinel onboarding, and only confirmed-onboarded workspaces are evaluated here. "
    "There is no CIS Azure Foundations Benchmark control covering Sentinel connector health; CIS is "
    "an infrastructure-configuration benchmark and does not include SIEM/XDR operational controls."
)
REMEDIATION = (
    "Open Microsoft Sentinel > Data connectors for the affected workspace, select the required "
    "connector, and complete or repair its connection so at least one of its log data types is "
    "Enabled and actively ingesting."
)
PLAYBOOK = "playbooks/cli/fix_az_secops_008.sh"
_RESOURCE_TYPE = "Microsoft.SecurityInsights/dataConnectors"
_WORKSPACE_TYPE = "Microsoft.OperationalInsights/workspaces"


def _connector_kind(connector: Any) -> str:
    return str(value(connector, "kind") or "").strip().lower()


def _connector_connected(connector: Any) -> bool:
    """A connector is considered connected when at least one data type is Enabled.

    Connectors without a typed data_types field (some connector kinds do not
    expose one in this API version) are treated as connected once present,
    since presence is the only signal available for that kind.
    """
    data_types = value(connector, "data_types")
    if data_types is None:
        return True
    states = []
    for attr in ("alerts", "logs"):
        entry = value(data_types, attr)
        if entry is not None:
            states.append(str(getattr(value(entry, "state"), "value", value(entry, "state")) or "").lower())
    if not states:
        return True
    return any(state == "enabled" for state in states)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return the findings attached to this rule's FAIL evaluations."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report, per onboarded Sentinel workspace and required connector, whether it is connected."""
    collector, policy, early = prepare(RULE_ID, _RESOURCE_TYPE, azure_client, subscription_id, build_collector)
    if early is not None:
        return early
    if not policy.required_sentinel_connectors:
        return [
            not_applicable(
                RULE_ID,
                subscription_scope_id(subscription_id),
                _RESOURCE_TYPE,
                POLICY_NOT_REQUIRED,
                "The security-operations policy requires no Sentinel data connectors.",
            )
        ]

    workspaces = collector.sentinel_onboarded_workspaces()
    if workspaces.status is CollectionStatus.FAILED:
        return [collection_failed(RULE_ID, _WORKSPACE_TYPE, subscription_id, workspaces)]
    evaluations: List[RuleEvaluation] = [
        scope_unknown(
            RULE_ID,
            workspace_resource_id(subscription_id, scope),
            _WORKSPACE_TYPE,
            "Sentinel onboarding could not be checked for this workspace.",
        )
        for scope in workspaces.failed_scopes
    ]
    if not workspaces.items:
        return evaluations or [no_resources_found(RULE_ID, _WORKSPACE_TYPE, subscription_id)]

    connectors = collector.sentinel_data_connectors(workspaces.items)
    per_workspace = connectors.items[0] if connectors.items else {}
    required_kinds = sorted(policy.required_sentinel_connectors)
    for workspace in workspaces.items:
        workspace_name = str(value(workspace, "name") or "")
        scope_key = workspace_scope_key(workspace)
        base_id = f"{value(workspace, 'id', '')}/providers/Microsoft.SecurityInsights/dataConnectors"
        if connectors.status is CollectionStatus.FAILED or scope_key in connectors.failed_scopes:
            evaluations.extend(
                scope_unknown(
                    RULE_ID,
                    f"{base_id}/{required}",
                    _RESOURCE_TYPE,
                    f"Sentinel data connectors could not be collected for workspace {scope_key}.",
                )
                for required in required_kinds
            )
            continue

        by_kind: Dict[str, List[Any]] = {}
        for connector in per_workspace.get(scope_key, ()):
            by_kind.setdefault(_connector_kind(connector), []).append(connector)
        for required in required_kinds:
            candidates = by_kind.get(required, [])
            connected = bool(candidates) and any(_connector_connected(c) for c in candidates)
            state = "connected" if connected else ("missing" if not candidates else "disconnected")
            evidence = {"workspace": scope_key, "connector_kind": required, "connector_state": state}
            resource_id = f"{base_id}/{required}"
            if connected:
                evaluations.append(passed(RULE_ID, resource_id, _RESOURCE_TYPE, evidence))
                continue
            finding = build_finding(
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                severity=SEVERITY,
                category=CATEGORY,
                resource_id=resource_id,
                resource_name=f"{workspace_name}/{required}",
                resource_type=_RESOURCE_TYPE,
                description=DESCRIPTION,
                remediation=REMEDIATION,
                playbook=PLAYBOOK,
                frameworks=FRAMEWORKS,
                scope=f"sentinel-workspace:{scope_key}",
                metadata={
                    "destination": scope_key,
                    "connector_kind": required,
                    "connector_state": state,
                    "permissions_required": ["Microsoft.SecurityInsights/dataConnectors/read"],
                    "unknown_reason": None,
                },
            )
            evaluations.append(failed(RULE_ID, finding, evidence))
    return evaluations
