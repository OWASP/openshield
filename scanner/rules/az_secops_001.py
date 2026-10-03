"""AZ-SECOPS-001: Subscription activity logs are not exported to an approved central destination."""

import logging
from typing import Any, Dict, List

from scanner.rules._security_operations_common import (
    build_collector,
    build_finding,
    is_usable,
    load_policy_from_env,
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
    """Flag a subscription with no activity-log export to any approved destination."""
    policy = load_policy_from_env(RULE_ID)
    if policy is None:
        return []

    collector = build_collector(azure_client, subscription_id)
    result = collector.subscription_diagnostic_settings()
    if not is_usable(result):
        logger.warning(
            "%s: subscription diagnostic settings unavailable (%s); result is UNKNOWN", RULE_ID, result.error_code
        )
        return []

    approved_hit = False
    for setting in result.items:
        if _destinations(setting) & policy.approved_destination_ids:
            approved_hit = True
            break

    if approved_hit:
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
    return [finding]
