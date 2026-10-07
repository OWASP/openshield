"""AZ-SECOPS-009: Sentinel lacks required high-severity analytics coverage."""

import logging
from typing import Any, Dict, List

from scanner.rules._security_operations_common import build_collector, build_finding, load_policy_from_env, value
from scanner.security_operations import CollectionStatus, workspace_scope_key

logger = logging.getLogger(__name__)

RULE_ID = "AZ-SECOPS-009"
RULE_NAME = "Sentinel Missing Required High-Severity Analytics Coverage"
SEVERITY = "HIGH"
CATEGORY = "Security Operations"
FRAMEWORKS = {"CIS": "N/A-SECOPS-009", "NIST": "DE.CM-1", "ISO27001": "A.8.16", "SOC2": "CC7.2"}
DESCRIPTION = (
    "A Sentinel-onboarded workspace has no enabled analytics (alert) rule with High severity "
    "covering an organisation-required detection use case (e.g. privileged-role-change, "
    "credential-abuse). Detection use cases are matched against each enabled rule's name and "
    "tactics; a use case present only as a disabled rule, or not present at all, provides no "
    "actual detection coverage. There is no CIS Azure Foundations Benchmark control for Sentinel "
    "analytics coverage; CIS is an infrastructure-configuration benchmark and does not evaluate "
    "SIEM detection content."
)
REMEDIATION = (
    "Create or enable a Sentinel scheduled analytics rule with High severity covering the missing "
    "detection use case:\n"
    "  az sentinel alert-rule create --resource-group <rg> --workspace-name <workspace> \\\n"
    "    --kind Scheduled --severity High --display-name <use-case-name> ..."
)
PLAYBOOK = "playbooks/cli/fix_az_secops_009.sh"

_HIGH_SEVERITY = {"high"}


def _rule_enabled(rule: Any) -> bool:
    return bool(value(rule, "enabled", False))


def _rule_severity(rule: Any) -> str:
    sev = value(rule, "severity")
    return str(getattr(sev, "value", sev) or "").strip().lower()


def _rule_covers(rule: Any, use_case: str) -> bool:
    display_name = str(value(rule, "display_name") or "").strip().lower()
    use_case_normalised = use_case.strip().lower().replace("-", " ").replace("_", " ")
    display_normalised = display_name.replace("-", " ").replace("_", " ")
    return use_case_normalised in display_normalised


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Flag Sentinel workspaces missing enabled High-severity coverage for a required use case."""
    policy = load_policy_from_env(RULE_ID)
    if policy is None:
        return []
    if not policy.required_high_severity_analytics:
        logger.info("%s: no required high-severity analytics configured; rule is not applicable", RULE_ID)
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

    rules_result = collector.sentinel_alert_rules(workspaces_result.items)
    if rules_result.status is CollectionStatus.FAILED:
        logger.warning(
            "%s: Sentinel analytics rules unavailable (%s); result is UNKNOWN", RULE_ID, rules_result.error_code
        )
        return []
    if not rules_result.items:
        return []

    per_workspace = rules_result.items[0]
    findings: List[Dict[str, Any]] = []
    for workspace in workspaces_result.items:
        scope_key = workspace_scope_key(workspace)
        if scope_key in rules_result.failed_scopes:
            logger.warning(
                "%s: analytics rule collection failed for %s; result is UNKNOWN for that scope", RULE_ID, scope_key
            )
            continue

        rules = per_workspace.get(scope_key, ())
        covering_enabled_high = [
            rule for rule in rules if _rule_enabled(rule) and _rule_severity(rule) in _HIGH_SEVERITY
        ]

        for use_case in policy.required_high_severity_analytics:
            if any(_rule_covers(rule, use_case) for rule in covering_enabled_high):
                continue
            findings.append(
                build_finding(
                    rule_id=RULE_ID,
                    rule_name=RULE_NAME,
                    severity=SEVERITY,
                    category=CATEGORY,
                    resource_id=(
                        f"{value(workspace, 'id', '')}/providers/Microsoft.SecurityInsights/alertRules/{use_case}"
                    ),
                    resource_name=f"{value(workspace, 'name', '')}/{use_case}",
                    resource_type="Microsoft.SecurityInsights/alertRules",
                    description=DESCRIPTION,
                    remediation=REMEDIATION,
                    playbook=PLAYBOOK,
                    frameworks=FRAMEWORKS,
                    scope=f"sentinel-workspace:{scope_key}",
                    metadata={
                        "destination": scope_key,
                        "use_case": use_case,
                        "required_high_severity_analytics": list(policy.required_high_severity_analytics),
                        "permissions_required": ["Microsoft.SecurityInsights/alertRules/read"],
                        "unknown_reason": None,
                    },
                )
            )
    return findings
