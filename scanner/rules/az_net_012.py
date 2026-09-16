"""AZ-NET-012: VNet flow logs not enabled."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

RULE_ID = "AZ-NET-012"
RULE_NAME = "VNet Flow Logs Not Enabled"
SEVERITY = "MEDIUM"
CATEGORY = "Network"
DESCRIPTION = (
    "Neither a VNet flow log nor an existing legacy NSG flow log covers this virtual network. "
    "Without flow logs, network traffic is not auditable and attacker movement cannot be "
    "reconstructed. Microsoft stopped new NSG flow log creation on 2025-06-30 and retires the "
    "feature entirely on 2027-09-30 - VNet flow logs are the current, supported mechanism."
)
REMEDIATION = (
    "Enable a VNet flow log via Network Watcher (do not create a new NSG flow log - Microsoft "
    "blocks new NSG flow log creation as of 2025-06-30). Run: "
    "az network watcher flow-log create --location <region> "
    "--resource-group <network-watcher-resource-group> --name <flow-log-name> "
    "--vnet <vnet-id> --enabled true --storage-account <storage-account-id>"
)
PLAYBOOK = "playbooks/cli/fix_az_net_012.sh"
FRAMEWORKS = {
    "CIS": "6.7",
    "NIST": "DE.CM-1",
    "ISO27001": "A.12.4.1",
    "SOC2": "CC7.2",
}

logger = logging.getLogger(__name__)


def _covered_by_enabled_flow_log(flow_logs: List[Any], target_id: str) -> bool:
    target_id = (target_id or "").lower()
    if not target_id:
        return False
    return any(
        str(getattr(flow_log, "target_resource_id", "") or "").lower() == target_id
        and bool(getattr(flow_log, "enabled", False))
        for flow_log in flow_logs
    )


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Scan all VNets for VNet-level flow logs, falling back to an existing
    (never newly created) legacy NSG flow log on one of the VNet's subnets."""
    findings: List[Dict[str, Any]] = []

    flow_logs_by_region = azure_client.get_flow_logs()

    for vnet in azure_client.get_virtual_networks():
        vnet_id = getattr(vnet, "id", "")
        parsed = azure_client.parse_resource_id(vnet_id)
        resource_group = parsed.get("resource_group", "")
        vnet_name = parsed.get("name", "")
        location = (getattr(vnet, "location", "") or "").lower().replace(" ", "")

        if not resource_group or not vnet_name or not location:
            continue

        region_flow_logs = flow_logs_by_region.get(location)
        if region_flow_logs is None:
            # No Network Watcher found for this region, or that region's
            # flow-log listing failed - coverage can't be determined, so this
            # VNet must not be flagged. (A missing Network Watcher is AZ-NET-011's
            # finding, not this rule's.)
            logger.warning(
                "%s UNKNOWN for %s: flow log evidence unavailable for region %s", RULE_ID, vnet_name, location
            )
            continue

        if _covered_by_enabled_flow_log(region_flow_logs, vnet_id):
            continue  # compliant: real VNet flow log

        nsg_ids = {
            getattr(getattr(subnet, "network_security_group", None), "id", "")
            for subnet in getattr(vnet, "subnets", []) or []
            if getattr(subnet, "network_security_group", None)
        }
        if any(_covered_by_enabled_flow_log(region_flow_logs, nsg_id) for nsg_id in nsg_ids):
            # An existing legacy NSG flow log already covers this VNet's
            # traffic. New NSG flow log creation is blocked, so this is
            # accepted as-is, not flagged for migration.
            continue

        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": vnet_id,
                "resource_name": vnet_name,
                "resource_type": "Microsoft.Network/virtualNetworks",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "metadata": {
                    "resource_group": resource_group,
                    "flow_logs_enabled": False,
                },
            }
        )

    return findings
