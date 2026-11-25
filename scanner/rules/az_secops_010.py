"""AZ-SECOPS-010: Security alerts have no monitored incident-response destination."""

import logging
from typing import Any, Dict, List

from scanner.evaluation import EVIDENCE_UNAVAILABLE, EvaluationStatus, RuleEvaluation, fail_findings
from scanner.rules._security_operations_common import (
    SUBSCRIPTION_RESOURCE_TYPE,
    build_collector,
    build_finding,
    collection_failed,
    failed,
    is_usable,
    passed,
    prepare,
    value,
)
from scanner.security_operations import CollectionStatus, workspace_scope_key

logger = logging.getLogger(__name__)

RULE_ID = "AZ-SECOPS-010"
RULE_NAME = "Security Alerts Have No Monitored Incident-Response Destination"
SEVERITY = "HIGH"
CATEGORY = "Security Operations"
FRAMEWORKS = {"CIS": "2.1.20", "NIST": "RS.CO-2", "ISO27001": "A.6.8", "SOC2": "CC7.4"}
DESCRIPTION = (
    "No enabled Azure Monitor action group with at least one notification receiver (email, SMS, "
    "voice, webhook, ITSM, Logic App, Automation runbook, Azure Function, or Event Hub) exists at "
    "subscription scope, and no Sentinel-onboarded workspace has an automation rule configured to "
    "route incidents onward (e.g. to a playbook). Without either mechanism, a security alert or "
    "Sentinel incident can be generated with nobody and nothing notified to respond to it."
)
REMEDIATION = (
    "Create an enabled Azure Monitor action group with at least one receiver, e.g.:\n"
    "  az monitor action-group create --name soc-notify --resource-group <rg> \\\n"
    "    --action email soc-oncall ops@example.com\n"
    "Or configure a Sentinel automation rule that runs a playbook when an incident is created:\n"
    "  az sentinel automation-rule create --resource-group <rg> --workspace-name <workspace> ..."
)
PLAYBOOK = "playbooks/cli/fix_az_secops_010.sh"

_RECEIVER_FIELDS = (
    "email_receivers",
    "sms_receivers",
    "webhook_receivers",
    "itsm_receivers",
    "azure_app_push_receivers",
    "automation_runbook_receivers",
    "voice_receivers",
    "logic_app_receivers",
    "azure_function_receivers",
    "event_hub_receivers",
)


def _action_group_is_monitored(group: Any) -> bool:
    if not value(group, "enabled", True):
        return False
    for field in _RECEIVER_FIELDS:
        receivers = value(group, field)
        if receivers:
            return True
    return False


def _automation_rule_coverage(automation_rules_result: Any, workspaces: Any) -> tuple[bool, bool]:
    """Return (has_coverage, evidence_is_complete) for Sentinel automation-rule routing.

    ``evidence_is_complete`` is False whenever any onboarded workspace's
    automation rules could not be collected (a PARTIAL result, or a workspace
    absent from an otherwise-COMPLETE result because its own scope failed).
    A caller must never treat incomplete evidence as proof of "no coverage":
    the workspace that could not be checked might be the one with the
    routing rule.
    """
    if automation_rules_result.status is CollectionStatus.FAILED or not automation_rules_result.items:
        return False, False
    per_workspace = automation_rules_result.items[0]
    has_coverage = False
    evidence_is_complete = True
    for workspace in workspaces:
        scope_key = workspace_scope_key(workspace)
        if scope_key in automation_rules_result.failed_scopes:
            evidence_is_complete = False
            continue
        if per_workspace.get(scope_key, ()):
            has_coverage = True
    return has_coverage, evidence_is_complete


def _unknown(resource_id: str, reason: str) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=RULE_ID,
        resource_id=resource_id,
        resource_type=SUBSCRIPTION_RESOURCE_TYPE,
        status=EvaluationStatus.UNKNOWN,
        reason_code=EVIDENCE_UNAVAILABLE,
        reason=reason,
    )


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return the findings attached to this rule's FAIL evaluations."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report whether the subscription routes incidents to a monitored destination.

    A monitored action group is enough for PASS. Without one, Sentinel
    automation rules are the second source of evidence; if that evidence
    cannot be read (fully or for some workspaces) the result is UNKNOWN,
    because the unreadable workspace might be the one that routes incidents.
    """
    collector, policy, early = prepare(
        RULE_ID, SUBSCRIPTION_RESOURCE_TYPE, azure_client, subscription_id, build_collector
    )
    if early is not None:
        return early

    resource_id = f"/subscriptions/{subscription_id}"
    action_groups = collector.action_groups()
    if action_groups.status is CollectionStatus.FAILED:
        return [collection_failed(RULE_ID, SUBSCRIPTION_RESOURCE_TYPE, subscription_id, action_groups)]
    monitored_groups = [g for g in action_groups.items if _action_group_is_monitored(g)]
    if monitored_groups:
        return [
            passed(
                RULE_ID,
                resource_id,
                SUBSCRIPTION_RESOURCE_TYPE,
                {"monitored_action_groups": len(monitored_groups), "action_groups_found": len(action_groups.items)},
            )
        ]

    workspaces = collector.sentinel_onboarded_workspaces()
    if not is_usable(workspaces):
        return [_unknown(resource_id, "No monitored action group, and Sentinel onboarding could not be checked.")]

    has_automation_coverage = False
    evidence_is_complete = True
    if workspaces.items:
        automation_rules = collector.sentinel_automation_rules(workspaces.items)
        if not is_usable(automation_rules):
            return [
                _unknown(resource_id, "No monitored action group, and Sentinel automation rules could not be read.")
            ]
        has_automation_coverage, evidence_is_complete = _automation_rule_coverage(automation_rules, workspaces.items)

    evidence = {
        "action_groups_found": len(action_groups.items),
        "monitored_action_groups": 0,
        "sentinel_onboarded_workspaces": len(workspaces.items),
        "sentinel_automation_rule_coverage": has_automation_coverage,
    }
    if has_automation_coverage:
        return [passed(RULE_ID, resource_id, SUBSCRIPTION_RESOURCE_TYPE, evidence)]
    if not evidence_is_complete or workspaces.status is CollectionStatus.PARTIAL:
        return [_unknown(resource_id, "No monitored action group, and some Sentinel workspaces could not be checked.")]

    finding = build_finding(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity=SEVERITY,
        category=CATEGORY,
        resource_id=resource_id,
        resource_name=subscription_id,
        resource_type=SUBSCRIPTION_RESOURCE_TYPE,
        description=DESCRIPTION,
        remediation=REMEDIATION,
        playbook=PLAYBOOK,
        frameworks=FRAMEWORKS,
        scope="subscription-incident-response-destination",
        metadata={
            "destination": "none-monitored",
            "action_groups_found": len(action_groups.items),
            "sentinel_automation_rule_coverage": has_automation_coverage,
            "permissions_required": [
                "Microsoft.Insights/actionGroups/read",
                "Microsoft.SecurityInsights/automationRules/read",
            ],
            "unknown_reason": None,
        },
    )
    return [failed(RULE_ID, finding, evidence)]
