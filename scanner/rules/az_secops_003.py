"""AZ-SECOPS-003: A critical resource lacks required diagnostic settings."""

import logging
from typing import Any, Dict, List, Sequence

from scanner.evaluation import RuleEvaluation, fail_findings
from scanner.rules._security_operations_common import (
    CRITICAL_RESOURCE_TYPE,
    build_collector,
    build_finding,
    destinations_of,
    evaluate_critical_resources,
    failed,
    passed,
    value,
)
from scanner.security_operations import SecurityOperationsPolicy

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


def _judge(resource_id: str, settings: Sequence[Any], policy: SecurityOperationsPolicy) -> RuleEvaluation:
    destinations = sorted({dest for setting in settings for dest in destinations_of(setting)})
    evidence = {"destinations": destinations, "diagnostic_settings_found": len(settings)}
    if _has_approved_export(settings, policy.approved_destination_ids):
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
        scope="critical-resource-diagnostics",
        metadata={
            "destination": "none-approved",
            "approved_destination_ids": sorted(policy.approved_destination_ids),
            "diagnostic_settings_found": len(settings),
            "permissions_required": ["Microsoft.Insights/diagnosticSettings/read"],
            "unknown_reason": None,
        },
    )
    return failed(RULE_ID, finding, evidence)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return the findings attached to this rule's FAIL evaluations."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report, per in-scope critical resource, whether its logs reach an approved destination."""
    return evaluate_critical_resources(RULE_ID, azure_client, subscription_id, build_collector, _judge)
