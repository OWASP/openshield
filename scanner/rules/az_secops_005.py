"""AZ-SECOPS-005: Security logs are stored only in a destination modifiable by workload administrators."""

import logging
from typing import Any, Dict, List, Optional

from scanner.rules._security_operations_common import (
    build_collector,
    build_finding,
    is_excluded,
    is_usable,
    load_policy_from_env,
    value,
)

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


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Flag critical resources whose only log export sits in the workload's own resource group."""
    policy = load_policy_from_env(RULE_ID)
    if policy is None:
        return []

    collector = build_collector(azure_client, subscription_id)
    critical_result = collector.critical_resource_ids(policy)
    if not is_usable(critical_result):
        logger.warning(
            "%s: critical resource inventory unavailable (%s); result is UNKNOWN", RULE_ID, critical_result.error_code
        )
        return []

    critical_ids = [rid for rid in critical_result.items if not is_excluded(rid, policy)]
    if not critical_ids:
        logger.info("%s: no in-scope critical resources; rule is not applicable", RULE_ID)
        return []

    diag_result = collector.resource_diagnostic_settings(critical_ids)
    if not is_usable(diag_result) or not diag_result.items:
        logger.warning(
            "%s: resource diagnostic settings unavailable (%s); result is UNKNOWN", RULE_ID, diag_result.error_code
        )
        return []

    per_resource = diag_result.items[0]
    findings: List[Dict[str, Any]] = []
    for resource_id in critical_ids:
        settings = per_resource.get(resource_id, ())
        if not settings:
            # No export at all is AZ-SECOPS-003's finding; nothing to say here.
            continue
        if _has_approved_destination(settings, policy.approved_destination_ids):
            continue
        if not _only_same_resource_group_destination(settings, resource_id):
            continue
        findings.append(
            build_finding(
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                severity=SEVERITY,
                category=CATEGORY,
                resource_id=resource_id,
                resource_name=resource_id.rsplit("/", 1)[-1],
                resource_type="critical-resource",
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
        )
    return findings
