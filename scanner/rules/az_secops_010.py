"""AZ-SECOPS-010: Security alerts have no monitored incident-response destination."""

import logging
from typing import Any, Dict, List

from scanner.rules._security_operations_common import (
    build_collector,
    build_finding,
    is_usable,
    load_policy_from_env,
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


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Flag a subscription with no monitored action group and no Sentinel automation-rule routing."""
    policy = load_policy_from_env(RULE_ID)
    if policy is None:
        return []

    collector = build_collector(azure_client, subscription_id)
    action_groups_result = collector.action_groups()
    if action_groups_result.status is CollectionStatus.FAILED:
        logger.warning(
            "%s: action groups unavailable (%s); result is UNKNOWN", RULE_ID, action_groups_result.error_code
        )
        return []

    has_monitored_action_group = any(_action_group_is_monitored(g) for g in action_groups_result.items)
    if has_monitored_action_group:
        return []

    # No action group covers it; a Sentinel automation rule routing incidents
    # onward is an accepted alternative destination, so check before failing.
    workspaces_result = collector.sentinel_onboarded_workspaces()
    if not is_usable(workspaces_result):
        logger.warning(
            "%s: Sentinel onboarding discovery unavailable (%s); result is UNKNOWN",
            RULE_ID,
            workspaces_result.error_code,
        )
        return []

    has_automation_coverage = False
    evidence_is_complete = True
    if workspaces_result.items:
        automation_rules_result = collector.sentinel_automation_rules(workspaces_result.items)
        if not is_usable(automation_rules_result):
            logger.warning(
                "%s: Sentinel automation rules unavailable (%s); result is UNKNOWN",
                RULE_ID,
                automation_rules_result.error_code,
            )
            return []
        has_automation_coverage, evidence_is_complete = _automation_rule_coverage(
            automation_rules_result, workspaces_result.items
        )

    if has_automation_coverage:
        return []

    # sentinel_onboarded_workspaces() itself can also be PARTIAL: some
    # workspaces were confirmed onboarded (and checked above), but others
    # could not be checked at all, so their automation-rule coverage is
    # completely unknown, not just incomplete.
    if not evidence_is_complete or workspaces_result.status is CollectionStatus.PARTIAL:
        logger.warning(
            "%s: incomplete Sentinel evidence (some workspace scopes unreachable); result is UNKNOWN", RULE_ID
        )
        return []

    finding = build_finding(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity=SEVERITY,
        category=CATEGORY,
        resource_id=f"/subscriptions/{subscription_id}",
        resource_name=subscription_id,
        resource_type="Microsoft.Resources/subscriptions",
        description=DESCRIPTION,
        remediation=REMEDIATION,
        playbook=PLAYBOOK,
        frameworks=FRAMEWORKS,
        scope="subscription-incident-response-destination",
        metadata={
            "destination": "none-monitored",
            "action_groups_found": len(action_groups_result.items),
            "sentinel_automation_rule_coverage": has_automation_coverage,
            "permissions_required": [
                "Microsoft.Insights/actionGroups/read",
                "Microsoft.SecurityInsights/automationRules/read",
            ],
            "unknown_reason": None,
        },
    )
    return [finding]
