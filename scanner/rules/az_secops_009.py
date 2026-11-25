"""AZ-SECOPS-009: Sentinel lacks required high-severity analytics coverage."""

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
_RESOURCE_TYPE = "Microsoft.SecurityInsights/alertRules"
_WORKSPACE_TYPE = "Microsoft.OperationalInsights/workspaces"

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
    """Return the findings attached to this rule's FAIL evaluations."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report, per onboarded Sentinel workspace and required use case, whether enabled High-severity coverage exists."""
    collector, policy, early = prepare(RULE_ID, _RESOURCE_TYPE, azure_client, subscription_id, build_collector)
    if early is not None:
        return early
    use_cases = list(dict.fromkeys(policy.required_high_severity_analytics))
    if not use_cases:
        return [
            not_applicable(
                RULE_ID,
                subscription_scope_id(subscription_id),
                _RESOURCE_TYPE,
                POLICY_NOT_REQUIRED,
                "The security-operations policy requires no High-severity analytics use cases.",
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

    rules_result = collector.sentinel_alert_rules(workspaces.items)
    per_workspace = rules_result.items[0] if rules_result.items else {}
    for workspace in workspaces.items:
        scope_key = workspace_scope_key(workspace)
        base_id = f"{value(workspace, 'id', '')}/providers/Microsoft.SecurityInsights/alertRules"
        if rules_result.status is CollectionStatus.FAILED or scope_key in rules_result.failed_scopes:
            evaluations.extend(
                scope_unknown(
                    RULE_ID,
                    f"{base_id}/{use_case}",
                    _RESOURCE_TYPE,
                    f"Sentinel analytics rules could not be collected for workspace {scope_key}.",
                )
                for use_case in use_cases
            )
            continue

        covering_enabled_high = [
            rule
            for rule in per_workspace.get(scope_key, ())
            if _rule_enabled(rule) and _rule_severity(rule) in _HIGH_SEVERITY
        ]
        for use_case in use_cases:
            resource_id = f"{base_id}/{use_case}"
            covering = [
                str(value(rule, "display_name") or "") for rule in covering_enabled_high if _rule_covers(rule, use_case)
            ]
            evidence = {"workspace": scope_key, "use_case": use_case, "covering_rules": covering}
            if covering:
                evaluations.append(passed(RULE_ID, resource_id, _RESOURCE_TYPE, evidence))
                continue
            finding = build_finding(
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                severity=SEVERITY,
                category=CATEGORY,
                resource_id=resource_id,
                resource_name=f"{value(workspace, 'name', '')}/{use_case}",
                resource_type=_RESOURCE_TYPE,
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
            evaluations.append(failed(RULE_ID, finding, evidence))
    return evaluations
