"""AZ-SECOPS-008: A required Microsoft Sentinel data connector is disconnected or unhealthy."""

import logging
from typing import Any, Dict, List

from scanner.rules._security_operations_common import build_collector, build_finding, load_policy_from_env, value
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
    """Flag required Sentinel connectors missing or unhealthy on onboarded workspaces."""
    policy = load_policy_from_env(RULE_ID)
    if policy is None:
        return []
    if not policy.required_sentinel_connectors:
        logger.info("%s: no required Sentinel connectors configured; rule is not applicable", RULE_ID)
        return []

    collector = build_collector(azure_client, subscription_id)
    workspaces_result = collector.sentinel_onboarded_workspaces()
    if workspaces_result.status is CollectionStatus.FAILED:
        logger.warning(
            "%s: Sentinel onboarding discovery unavailable (%s); result is UNKNOWN",
            RULE_ID,
            workspaces_result.error_code,
        )
        return []
    if not workspaces_result.items:
        logger.info("%s: no Sentinel-onboarded workspaces found; rule is not applicable", RULE_ID)
        return []

    connectors_result = collector.sentinel_data_connectors(workspaces_result.items)
    if connectors_result.status is CollectionStatus.FAILED:
        logger.warning(
            "%s: Sentinel data connectors unavailable (%s); result is UNKNOWN", RULE_ID, connectors_result.error_code
        )
        return []
    if not connectors_result.items:
        return []

    per_workspace = connectors_result.items[0]
    findings: List[Dict[str, Any]] = []
    for workspace in workspaces_result.items:
        workspace_name = str(value(workspace, "name") or "")
        scope_key = workspace_scope_key(workspace)
        if scope_key in connectors_result.failed_scopes:
            logger.warning(
                "%s: connector collection failed for %s; result is UNKNOWN for that scope", RULE_ID, scope_key
            )
            continue

        connectors = per_workspace.get(scope_key, ())
        by_kind = {}
        for connector in connectors:
            by_kind.setdefault(_connector_kind(connector), []).append(connector)

        for required in sorted(policy.required_sentinel_connectors):
            candidates = by_kind.get(required, [])
            if candidates and any(_connector_connected(c) for c in candidates):
                continue
            state = "missing" if not candidates else "disconnected"
            findings.append(
                build_finding(
                    rule_id=RULE_ID,
                    rule_name=RULE_NAME,
                    severity=SEVERITY,
                    category=CATEGORY,
                    resource_id=(
                        f"{value(workspace, 'id', '')}/providers/Microsoft.SecurityInsights/dataConnectors/{required}"
                    ),
                    resource_name=f"{workspace_name}/{required}",
                    resource_type="Microsoft.SecurityInsights/dataConnectors",
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
            )
    return findings
