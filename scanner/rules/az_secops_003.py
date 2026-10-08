"""AZ-SECOPS-003: A critical resource lacks required diagnostic settings."""

import logging
from typing import Any, Dict, List

from scanner.rules._security_operations_common import (
    build_collector,
    build_finding,
    is_excluded,
    is_usable,
    load_policy_from_env,
    value,
)

logger = logging.getLogger(__name__)

RULE_ID = "AZ-SECOPS-003"
RULE_NAME = "Critical Resource Missing Required Diagnostic Settings"
SEVERITY = "HIGH"
CATEGORY = "Security Operations"
FRAMEWORKS = {"CIS": "5.4", "NIST": "DE.AE-3", "ISO27001": "A.8.15", "SOC2": "CC7.2"}
DESCRIPTION = (
    "A resource of an organisation-defined critical type has no diagnostic setting exporting to "
    "an approved central destination. Critical resources (e.g. Key Vaults, SQL servers, Storage "
    "accounts) without diagnostic export are invisible to central detection even when subscription "
    "activity logging is otherwise correctly configured."
)
REMEDIATION = (
    "Create a diagnostic setting on the resource that sends logs to an approved destination, e.g.:\n"
    "  az monitor diagnostic-settings create \\\n"
    "    --name central-security-export \\\n"
    "    --resource <resource-id> \\\n"
    "    --workspace <approved-log-analytics-workspace-resource-id> \\\n"
    '    --logs \'[{"categoryGroup":"allLogs","enabled":true}]\''
)
PLAYBOOK = "playbooks/cli/fix_az_secops_003.sh"


def _has_approved_export(settings: Any, approved_destination_ids: frozenset) -> bool:
    for setting in settings or ():
        for field in ("workspace_id", "storage_account_id", "event_hub_authorization_rule_id"):
            dest = value(setting, field)
            if dest and str(dest).strip().lower() in approved_destination_ids:
                return True
    return False


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Flag critical resources with no diagnostic setting at an approved destination."""
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
        if _has_approved_export(settings, policy.approved_destination_ids):
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
                scope="critical-resource-diagnostics",
                metadata={
                    "destination": "none-approved",
                    "approved_destination_ids": sorted(policy.approved_destination_ids),
                    "diagnostic_settings_found": len(settings),
                    "permissions_required": ["Microsoft.Insights/diagnosticSettings/read"],
                    "unknown_reason": None,
                },
            )
        )
    return findings
