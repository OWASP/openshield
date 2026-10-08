"""AZ-NET-007: Application Gateway without WAF enabled."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-NET-007"
RULE_NAME = "Application Gateway without WAF enabled"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "9.6", "NIST": "SI-3", "ISO27001": "A.8.20"}
DESCRIPTION = (
    "An Application Gateway exists without Web Application Firewall enabled. "
    "Without WAF, the application is unprotected against common web exploits "
    "such as SQL injection, cross-site scripting and OWASP Top 10 attacks. "
    "Any public-facing application behind an Application Gateway should have "
    "WAF enabled in Prevention mode."
)
REMEDIATION = (
    "Upgrade the Application Gateway SKU to WAF_v2 and enable WAF in "
    "Prevention mode. Configure the OWASP core rule set and review any "
    "false positives before enabling Prevention mode in production."
)
PLAYBOOK = "playbooks/cli/fix_az_net_007.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect Application Gateways without WAF enabled."""
    findings: List[Dict[str, Any]] = []

    try:
        from azure.mgmt.network import NetworkManagementClient

        client = NetworkManagementClient(azure_client.credential, azure_client.subscription_id)
        app_gateways = list(client.application_gateways.list_all())
    except Exception as exc:
        logger.error("Failed to list application gateways: %s", exc)
        return findings

    for agw in app_gateways:
        sku = getattr(agw, "sku", None)
        sku_name = getattr(sku, "name", "") if sku else ""
        waf_config = getattr(agw, "web_application_firewall_configuration", None)
        waf_enabled = getattr(waf_config, "enabled", False) if waf_config else False

        if "WAF" not in sku_name or not waf_enabled:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": getattr(agw, "id", ""),
                    "resource_name": getattr(agw, "name", ""),
                    "resource_type": "Microsoft.Network/applicationGateways",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "sku": sku_name,
                        "waf_enabled": waf_enabled,
                        "location": getattr(agw, "location", ""),
                    },
                }
            )

    return findings
