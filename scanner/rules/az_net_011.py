"""AZ-NET-011: Network Watcher not enabled in all regions."""

from typing import Any, Dict, List

RULE_ID = "AZ-NET-011"
RULE_NAME = "Network Watcher Not Enabled in All Regions"
SEVERITY = "LOW"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "6.5", "NIST": "DE.CM-7", "ISO27001": "A.8.15", "SOC2": "CC7.2"}
DESCRIPTION = (
    "Network Watcher is not enabled in one or more Azure regions where resources "
    "are deployed. Network Watcher provides network monitoring, diagnostics, and "
    "logging capabilities. Without it, network-level incidents cannot be "
    "investigated or diagnosed."
)
REMEDIATION = (
    "Enable Network Watcher in all regions where Azure resources are deployed. "
    "Run: az network watcher configure --resource-group NetworkWatcherRG "
    "--locations <region> --enabled true"
)
PLAYBOOK = "playbooks/cli/fix_az_net_011.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect regions where resources exist but Network Watcher is not enabled."""
    findings: List[Dict[str, Any]] = []

    regions_with_resources = azure_client.get_regions_with_resources()
    regions_with_watcher = azure_client.get_network_watcher_regions()

    unmonitored_regions = set(regions_with_resources) - set(regions_with_watcher)

    for region in sorted(unmonitored_regions):
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": f"/subscriptions/{subscription_id}/regions/{region}",
                "resource_name": region,
                "resource_type": "Microsoft.Network/networkWatchers",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {"region": region},
            }
        )

    return findings
