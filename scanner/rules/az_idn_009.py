"""AZ-IDN-009: No activity log alert for role assignment changes in subscription."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-IDN-009"
RULE_NAME = "No Activity Log Alert for Role Assignment Changes"
SEVERITY = "MEDIUM"
CATEGORY = "Identity"
FRAMEWORKS = {"CIS": "5.2.1", "NIST": "DE.CM-3", "ISO27001": "A.8.16", "SOC2": "CC7.2"}
DESCRIPTION = (
    "The subscription has no activity log alert configured for role assignment "
    "changes (Microsoft.Authorization/roleAssignments/write). Without alerting on "
    "privilege escalation events, an attacker who gains access and elevates their "
    "own permissions will go undetected. This is a required detective control under "
    "CIS Azure Benchmark 5.2.1 and NIST DE.CM-3."
)
REMEDIATION = (
    "Create an activity log alert for role assignment write events. Run: "
    "az monitor activity-log alert create "
    "--name 'Alert-RoleAssignment-Write' "
    "--resource-group <rg-name> "
    "--scope /subscriptions/<subscription-id> "
    "--condition category=Administrative "
    "operationName=Microsoft.Authorization/roleAssignments/write "
    "--action-group <action-group-id>. "
    "Ensure the action group routes alerts to a monitored channel such as email or "
    "a ticketing integration."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_009.sh"

logger = logging.getLogger(__name__)

TARGET_OPERATION = "Microsoft.Authorization/roleAssignments/write"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect subscriptions with no activity log alert for role assignment changes."""
    findings: List[Dict[str, Any]] = []

    try:
        from azure.mgmt.monitor import MonitorManagementClient

        monitor_client = MonitorManagementClient(azure_client.credential, subscription_id)
        alerts = list(monitor_client.activity_log_alerts.list_by_subscription_id())
    except Exception as exc:
        logger.error("AZ-IDN-009: Failed to list activity log alerts: %s", exc)
        return findings

    for alert in alerts:
        if not getattr(alert, "enabled", True):
            continue

        condition = getattr(alert, "condition", None)
        if condition is None:
            continue

        all_of = getattr(condition, "all_of", []) or []
        operations = [
            leaf.equals
            for leaf in all_of
            if getattr(leaf, "field", "") == "operationName" and getattr(leaf, "equals", "")
        ]

        if any(op.lower() == TARGET_OPERATION.lower() for op in operations):
            return findings

    findings.append(
        {
            "rule_id": RULE_ID,
            "rule_name": RULE_NAME,
            "severity": SEVERITY,
            "category": CATEGORY,
            "resource_id": f"/subscriptions/{subscription_id}",
            "resource_name": f"subscription/{subscription_id}",
            "resource_type": "Microsoft.Insights/activityLogAlerts",
            "description": DESCRIPTION,
            "remediation": REMEDIATION,
            "playbook": PLAYBOOK,
            "frameworks": FRAMEWORKS,
            "metadata": {
                "subscription_id": subscription_id,
                "missing_operation": TARGET_OPERATION,
            },
        }
    )

    return findings
