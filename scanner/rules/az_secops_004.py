"""AZ-SECOPS-004: Security logs have insufficient retention."""

import logging
from typing import Any, Dict, List, Sequence

from scanner.evaluation import NO_RESOURCES_FOUND, RuleEvaluation, fail_findings
from scanner.rules._security_operations_common import (
    CRITICAL_RESOURCE_TYPE,
    build_collector,
    build_finding,
    evaluate_critical_resources,
    failed,
    not_applicable,
    passed,
    value,
)
from scanner.security_operations import SecurityOperationsPolicy

logger = logging.getLogger(__name__)

RULE_ID = "AZ-SECOPS-004"
RULE_NAME = "Security Logs Have Insufficient Retention"
SEVERITY = "MEDIUM"
CATEGORY = "Security Operations"
FRAMEWORKS = {"CIS": "N/A-SECOPS-004", "NIST": "PR.PT-1", "ISO27001": "A.8.15", "SOC2": "CC7.2"}
DESCRIPTION = (
    "A diagnostic setting exporting security-relevant logs to a Storage Account has a retention "
    "policy configured below the organisation's minimum retention requirement (or retention is "
    "disabled entirely). Insufficient retention limits how far back an investigation can look once "
    "an incident is detected. Log Analytics workspace retention is governed by the workspace's own "
    "retention setting rather than the diagnostic setting's retention_policy field and is evaluated "
    "separately; this rule covers the Storage Account destination retention_policy field only. "
    "CIS Azure Foundations Benchmark control 5.1.1 covers the existence of a diagnostic setting "
    "(AZ-SECOPS-001) and does not assign a distinct numbered control ID to the retention duration "
    "itself, so no single-control CIS mapping applies here."
)
REMEDIATION = (
    "Increase the diagnostic setting's Storage Account retention to at least the organisation's "
    "minimum, e.g.:\n"
    "  az monitor diagnostic-settings update \\\n"
    "    --name <setting-name> \\\n"
    "    --resource <resource-id> \\\n"
    '    --logs \'[{"categoryGroup":"allLogs","enabled":true,'
    '"retentionPolicy":{"enabled":true,"days":<minimum-retention-days>}}]\''
)
PLAYBOOK = "playbooks/cli/fix_az_secops_004.sh"


def _insufficient_storage_retentions(settings: Any, minimum_days: int) -> List[Dict[str, Any]]:
    """Return log entries whose Storage Account retention_policy is below minimum_days.

    Only settings that actually target a Storage Account are evaluated: a
    setting exporting solely to Log Analytics or Event Hub has no
    retention_policy semantics of its own (see DESCRIPTION).
    """
    violations = []
    for setting in settings or ():
        if not value(setting, "storage_account_id"):
            continue
        for log in value(setting, "logs", []) or []:
            if not value(log, "enabled", False):
                continue
            retention = value(log, "retention_policy")
            enabled = value(retention, "enabled", False) if retention is not None else False
            days = value(retention, "days", 0) if retention is not None else 0
            if not enabled or int(days or 0) < minimum_days:
                violations.append(
                    {
                        "category": value(log, "category") or value(log, "category_group") or "unknown",
                        "retention_enabled": bool(enabled),
                        "retention_days": int(days or 0),
                    }
                )
    return violations


def _storage_log_exports(settings: Sequence[Any]) -> int:
    """Count enabled log entries exported to a Storage Account (the only ones this rule judges)."""
    count = 0
    for setting in settings or ():
        if not value(setting, "storage_account_id"):
            continue
        count += sum(1 for log in value(setting, "logs", []) or [] if value(log, "enabled", False))
    return count


def _judge(resource_id: str, settings: Sequence[Any], policy: SecurityOperationsPolicy) -> RuleEvaluation:
    storage_exports = _storage_log_exports(settings)
    if not storage_exports:
        return not_applicable(
            RULE_ID,
            resource_id,
            CRITICAL_RESOURCE_TYPE,
            NO_RESOURCES_FOUND,
            "The resource has no enabled log export to a Storage Account, so there is no retention to check.",
        )
    violations = _insufficient_storage_retentions(settings, policy.minimum_retention_days)
    evidence = {
        "storage_log_exports": storage_exports,
        "minimum_retention_days": policy.minimum_retention_days,
        "violations": violations,
    }
    if not violations:
        return passed(RULE_ID, resource_id, CRITICAL_RESOURCE_TYPE, evidence)
    finding = build_finding(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity=SEVERITY,
        category=CATEGORY,
        resource_id=resource_id,
        resource_name=resource_id.rsplit("/", 1)[-1],
        resource_type=CRITICAL_RESOURCE_TYPE,
        description=DESCRIPTION,
        remediation=REMEDIATION,
        playbook=PLAYBOOK,
        frameworks=FRAMEWORKS,
        scope="critical-resource-log-retention",
        metadata={
            "retention": violations,
            "minimum_retention_days": policy.minimum_retention_days,
            "permissions_required": ["Microsoft.Insights/diagnosticSettings/read"],
            "unknown_reason": None,
        },
    )
    return failed(RULE_ID, finding, evidence)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return the findings attached to this rule's FAIL evaluations."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report, per in-scope critical resource, whether its Storage log exports meet minimum retention."""
    return evaluate_critical_resources(RULE_ID, azure_client, subscription_id, build_collector, _judge)
