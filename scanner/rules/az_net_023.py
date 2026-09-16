"""AZ-NET-023: Azure Firewall threat intelligence is not in Deny mode."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from scanner.rules._perimeter_common import metadata

RULE_ID = "AZ-NET-023"
RULE_NAME = "Azure Firewall Threat Intelligence Is Not in Deny Mode"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "N/A-NET-023", "NIST": "DE.CM-1", "ISO27001": "A.13.1.1", "SOC2": "CC6.6"}
DESCRIPTION = (
    "Azure Firewall threat intelligence is disabled or configured to alert without denying known malicious traffic."
)
REMEDIATION = "Set Azure Firewall threat intelligence mode to Deny after reviewing documented exception traffic."
PLAYBOOK = "playbooks/cli/fix_az_net_023.sh"
logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    firewalls = azure_client.get_all_azure_firewalls()
    if firewalls is None:
        logger.warning("%s UNKNOWN: Azure Firewall inventory unavailable", RULE_ID)
        return []
    timestamp = datetime.now(timezone.utc).isoformat()
    findings = []
    for firewall in firewalls:
        mode = getattr(firewall, "threat_intel_mode", None)
        if mode is None:
            logger.warning(
                "%s UNKNOWN for %s: threat intelligence state missing", RULE_ID, getattr(firewall, "name", "")
            )
            continue
        normalized = str(getattr(mode, "value", mode)).lower()
        if normalized == "deny":
            continue
        if normalized not in {"alert", "off"}:
            logger.warning(
                "%s UNKNOWN for %s: unrecognized threat intelligence mode %r",
                RULE_ID,
                getattr(firewall, "name", ""),
                mode,
            )
            continue
        resource_id = getattr(firewall, "id", "") or ""
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": resource_id,
                "resource_name": getattr(firewall, "name", ""),
                "resource_type": "Microsoft.Network/azureFirewalls",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": metadata(
                    resource_id=resource_id,
                    observed={"threat_intel_mode": str(mode)},
                    expected={"threat_intel_mode": "Deny"},
                    source="Azure Resource Manager: Microsoft.Network/azureFirewalls",
                    timestamp=timestamp,
                    permissions=["Microsoft.Network/azureFirewalls/read"],
                ),
            }
        )
    return findings
