"""AZ-SECOPS-001: Subscription activity logs are not exported to an approved central destination."""

import logging
from typing import Any, Dict, List

from scanner.evaluation import RuleEvaluation, fail_findings
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

logger = logging.getLogger(__name__)

RULE_ID = "AZ-SECOPS-001"
RULE_NAME = "Subscription Activity Log Not Exported to an Approved Central Destination"
SEVERITY = "HIGH"
CATEGORY = "Security Operations"
FRAMEWORKS = {"CIS": "5.1.1", "NIST": "PR.PT-1", "ISO27001": "A.8.15", "SOC2": "CC7.2"}
DESCRIPTION = (
    "The subscription's Azure Activity Log has no diagnostic setting exporting it to an "
    "organisation-approved central destination (Log Analytics workspace, Storage Account, or "
    "Event Hub). Without a central export, subscription-level administrative, security, and "
    "policy events are only retained for the Activity Log's fixed default window and are not "
    "available to the SIEM/central security tooling used for detection and investigation."
)
REMEDIATION = (
    "Create a diagnostic setting on the subscription's Activity Log that sends all required log "
    "categories to an approved central destination, e.g.:\n"
    "  az monitor diagnostic-settings subscription create \\\n"
    "    --name central-security-export \\\n"
    "    --location <region> \\\n"
    "    --workspace <approved-log-analytics-workspace-resource-id>"
)
PLAYBOOK = "playbooks/cli/fix_az_secops_001.sh"


def _destinations(setting: Any) -> set:
    destinations = set()
    for field in ("workspace_id", "storage_account_id", "event_hub_authorization_rule_id"):
        dest = value(setting, field)
        if dest:
            destinations.add(str(dest).strip().lower())
    return destinations


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return the findings attached to this rule's FAIL evaluations."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report whether the subscription's activity log is exported to an approved destination."""
    collector, policy, early = prepare(
        RULE_ID, SUBSCRIPTION_RESOURCE_TYPE, azure_client, subscription_id, build_collector
    )
    if early is not None:
        return early

    result = collector.subscription_diagnostic_settings()
    if not is_usable(result):
        return [collection_failed(RULE_ID, SUBSCRIPTION_RESOURCE_TYPE, subscription_id, result)]

    destinations = sorted({dest for setting in result.items for dest in _destinations(setting)})
    approved = sorted(set(destinations) & policy.approved_destination_ids)
    evidence = {"destinations": destinations, "diagnostic_settings_found": len(result.items)}
    resource_id = f"/subscriptions/{subscription_id}"
    if approved:
        return [
            passed(RULE_ID, resource_id, SUBSCRIPTION_RESOURCE_TYPE, {**evidence, "approved_destinations": approved})
        ]

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
        scope="subscription-activity-log",
        metadata={
            "destination": "none-approved",
            "approved_destination_ids": sorted(policy.approved_destination_ids),
            "diagnostic_settings_found": len(result.items),
            "collection_status": result.status.value,
            "permissions_required": ["Microsoft.Insights/diagnosticSettings/read"],
            "unknown_reason": None,
        },
    )
    return [failed(RULE_ID, finding, evidence)]
