"""AZ-SECOPS-002: Required administrative, security, policy, or service-health categories are missing."""

import logging
from typing import Any, Dict, List

from scanner.rules._security_operations_common import (
    build_collector,
    build_finding,
    enum_value,
    is_usable,
    load_policy_from_env,
    value,
)

logger = logging.getLogger(__name__)

RULE_ID = "AZ-SECOPS-002"
RULE_NAME = "Required Activity Log Categories Missing From Central Export"
SEVERITY = "HIGH"
CATEGORY = "Security Operations"
FRAMEWORKS = {"CIS": "5.1.2", "NIST": "PR.PT-1", "ISO27001": "A.8.15", "SOC2": "CC7.2"}
DESCRIPTION = (
    "The subscription's Activity Log diagnostic setting(s) exporting to an approved destination "
    "do not enable every organisation-required log category (e.g. Administrative, Security, "
    "Policy, ServiceHealth). A partial category export leaves gaps in the events available for "
    "detection and investigation even though an export destination exists."
)
REMEDIATION = (
    "Update the Activity Log diagnostic setting to enable every required category, e.g.:\n"
    "  az monitor diagnostic-settings subscription update \\\n"
    "    --name <setting-name> \\\n"
    '    --logs \'[{"category":"Administrative","enabled":true},'
    '{"category":"Security","enabled":true},{"category":"Policy","enabled":true},'
    '{"category":"ServiceHealth","enabled":true}]\''
)
PLAYBOOK = "playbooks/cli/fix_az_secops_002.sh"


def _enabled_categories_at_approved_destinations(settings: Any, approved_destination_ids: frozenset) -> set:
    enabled: set = set()
    for setting in settings:
        destinations = set()
        for field in ("workspace_id", "storage_account_id", "event_hub_authorization_rule_id"):
            dest = value(setting, field)
            if dest:
                destinations.add(str(dest).strip().lower())
        if not destinations & approved_destination_ids:
            continue
        for log in value(setting, "logs", []) or []:
            if value(log, "enabled", False):
                category = value(log, "category") or value(log, "category_group")
                if category:
                    enabled.add(str(enum_value(category) or category).strip().lower())
    return enabled


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Flag missing required activity-log categories among approved-destination exports."""
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

    enabled = _enabled_categories_at_approved_destinations(result.items, policy.approved_destination_ids)
    if not enabled:
        # AZ-SECOPS-001 already reports the missing-export case; avoid a
        # duplicate, less-specific finding here when there is no approved
        # export to evaluate categories against.
        return []

    missing = {c for c in policy.required_activity_categories if c not in enabled}
    if not missing:
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
            "category": sorted(missing),
            "enabled_categories": sorted(enabled),
            "required_categories": sorted(policy.required_activity_categories),
            "permissions_required": ["Microsoft.Insights/diagnosticSettings/read"],
            "unknown_reason": None,
        },
    )
    return [finding]
