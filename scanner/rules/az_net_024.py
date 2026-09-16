"""AZ-NET-024: Application Gateway WAF is not in Prevention mode."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from scanner.rules._perimeter_common import REQUIRED_NETWORK_PERMISSIONS, metadata, policy_by_id, waf_enabled

RULE_ID = "AZ-NET-024"
RULE_NAME = "Application Gateway WAF Is Not in Prevention Mode"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "N/A-NET-024", "NIST": "PR.PT-4", "ISO27001": "A.13.1.1", "SOC2": "CC6.6"}
DESCRIPTION = "An enabled Application Gateway WAF is operating in Detection rather than Prevention mode."
REMEDIATION = (
    "Tune exclusions in a non-production environment, then set the inline WAF "
    "or associated WAF policy to Prevention mode."
)
PLAYBOOK = "playbooks/cli/fix_az_net_024.sh"
logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    gateways = azure_client.get_application_gateways()
    policies = azure_client.get_waf_policies()
    if gateways is None or policies is None:
        logger.warning("%s UNKNOWN: Application Gateway or WAF policy inventory unavailable", RULE_ID)
        return []
    indexed = policy_by_id(policies)
    timestamp = datetime.now(timezone.utc).isoformat()
    findings = []
    for gateway in gateways:
        if not waf_enabled(gateway):
            continue
        policy_id = getattr(getattr(gateway, "firewall_policy", None), "id", "") or ""
        policy = indexed.get(policy_id.lower())
        mode = getattr(getattr(policy, "policy_settings", None), "mode", None) if policy else None
        if mode is None:
            mode = getattr(getattr(gateway, "web_application_firewall_configuration", None), "firewall_mode", None)
        if mode is None:
            logger.warning("%s UNKNOWN for %s: WAF mode missing", RULE_ID, getattr(gateway, "name", ""))
            continue
        if str(getattr(mode, "value", mode)).lower() == "prevention":
            continue
        resource_id = getattr(gateway, "id", "") or ""
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": resource_id,
                "resource_name": getattr(gateway, "name", ""),
                "resource_type": "Microsoft.Network/applicationGateways",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": metadata(
                    resource_id=resource_id,
                    observed={"waf_mode": str(mode)},
                    expected={"waf_mode": "Prevention"},
                    source="Azure Resource Manager: Application Gateway and WAF policy",
                    timestamp=timestamp,
                    permissions=REQUIRED_NETWORK_PERMISSIONS,
                ),
            }
        )
    return findings
