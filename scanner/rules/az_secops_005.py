"""AZ-SECOPS-005: Security logs are stored only in a destination modifiable by workload administrators."""

import logging
from typing import Any, Dict, List, Optional, Sequence

from scanner.evaluation import NO_RESOURCES_FOUND, RuleEvaluation, fail_findings
from scanner.rules._security_operations_common import (
    CRITICAL_RESOURCE_TYPE,
    build_collector,
    build_finding,
    destinations_of,
    evaluate_critical_resources,
    failed,
    not_applicable,
    passed,
    value,
)
from scanner.security_operations import SecurityOperationsPolicy

logger = logging.getLogger(__name__)

RULE_ID = "AZ-SECOPS-005"
RULE_NAME = "Security Logs Stored Only in a Destination the Workload Administrator Can Modify"
SEVERITY = "HIGH"
CATEGORY = "Security Operations"
FRAMEWORKS = {"CIS": "N/A-SECOPS-005", "NIST": "PR.DS-6", "ISO27001": "A.8.15", "SOC2": "CC7.2"}
DESCRIPTION = (
    "A critical resource's diagnostic setting exports logs only to a destination that lives in "
    "the same resource group (and therefore the same administrative scope) as the workload itself, "
    "and no copy reaches an organisation-approved, centrally-owned destination. An administrator "
    "with Contributor/Owner on the workload's own resource group can delete or alter that "
    "destination's contents, defeating tamper-evidence for security-relevant logs. This is a "
    "resource-group/ownership comparison, not a live Storage immutability-policy read: the "
    "Monitor diagnostic-settings API does not expose the destination's own access-control or "
    "immutability configuration. The CIS Azure Foundations Benchmark does not assign a distinct "
    "numbered control to log-destination ownership/tamper-protection, so no single-control CIS "
    "mapping applies here; ISO 27001:2022 A.8.15 (Logging, which also covers protection of log information) "
    "is the closest direct match."
)
REMEDIATION = (
    "Add a second export from the resource's diagnostic setting to an organisation-approved, "
    "centrally-owned destination that the workload's administrators do not control, e.g.:\n"
    "  az monitor diagnostic-settings update \\\n"
    "    --name <setting-name> \\\n"
    "    --resource <resource-id> \\\n"
    "    --workspace <approved-log-analytics-workspace-resource-id>\n"
    "Consider enabling an immutability policy on any Storage Account destination as defence in depth."
)
PLAYBOOK = "playbooks/cli/fix_az_secops_005.sh"


def _resource_group_of(resource_id: str) -> Optional[str]:
    parts = str(resource_id or "").split("/")
    try:
        idx = [p.lower() for p in parts].index("resourcegroups")
        return parts[idx + 1].lower()
    except (ValueError, IndexError):
        return None


def _has_approved_destination(settings: Any, approved_destination_ids: frozenset) -> bool:
    for setting in settings or ():
        for field in ("workspace_id", "storage_account_id", "event_hub_authorization_rule_id"):
            dest = value(setting, field)
            if dest and str(dest).strip().lower() in approved_destination_ids:
                return True
    return False


def _only_same_resource_group_destination(settings: Any, resource_id: str) -> bool:
    """True when every configured destination sits in the workload's own resource group."""
    workload_rg = _resource_group_of(resource_id)
    destinations = []
    for setting in settings or ():
        for field in ("workspace_id", "storage_account_id", "event_hub_authorization_rule_id"):
            dest = value(setting, field)
            if dest:
                destinations.append(str(dest))
    if not destinations or workload_rg is None:
        return False
    return all(_resource_group_of(dest) == workload_rg for dest in destinations)


def _judge(resource_id: str, settings: Sequence[Any], policy: SecurityOperationsPolicy) -> RuleEvaluation:
    if not settings:
        return not_applicable(
            RULE_ID,
            resource_id,
            CRITICAL_RESOURCE_TYPE,
            NO_RESOURCES_FOUND,
            "The resource has no diagnostic export at all; AZ-SECOPS-003 reports that.",
        )
    destinations = sorted({dest for setting in settings for dest in destinations_of(setting)})
    approved = _has_approved_destination(settings, policy.approved_destination_ids)
    workload_owned_only = _only_same_resource_group_destination(settings, resource_id)
    evidence = {
        "destinations": destinations,
        "approved_destination": approved,
        "workload_owned_only": workload_owned_only,
    }
    if approved or not workload_owned_only:
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
        scope="critical-resource-log-destination-ownership",
        metadata={
            "destination": "workload-owned-only",
            "ownership": "workload-administrator",
            "approved_destination_ids": sorted(policy.approved_destination_ids),
            "permissions_required": ["Microsoft.Insights/diagnosticSettings/read"],
            "unknown_reason": None,
        },
    )
    return failed(RULE_ID, finding, evidence)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return the findings attached to this rule's FAIL evaluations."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report, per in-scope critical resource, whether its only log export is workload-owned."""
    return evaluate_critical_resources(RULE_ID, azure_client, subscription_id, build_collector, _judge)
