"""AZ-NET-025: WAF diagnostic logging is incomplete."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from scanner.rules._perimeter_common import metadata, waf_enabled

RULE_ID = "AZ-NET-025"
RULE_NAME = "Application Gateway WAF Diagnostic Logging Is Not Enabled"
SEVERITY = "MEDIUM"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "N/A-NET-025", "NIST": "DE.CM-1", "ISO27001": "A.12.4.1", "SOC2": "CC7.2"}
DESCRIPTION = (
    "An Application Gateway WAF lacks a diagnostic setting with every log category supported by its SKU enabled. "
    "WAF v1 requires access, performance, and firewall logs; WAF_v2 requires access and firewall logs, with "
    "performance telemetry provided through Azure Monitor metrics."
)
REMEDIATION = (
    "Create an Azure Monitor diagnostic setting that exports all log categories supported by the Application "
    "Gateway SKU to an approved destination, and retain Azure Monitor metrics for v2 performance telemetry."
)
PLAYBOOK = "playbooks/cli/fix_az_net_025.sh"
logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    gateways = azure_client.get_application_gateways()
    if gateways is None:
        logger.warning("%s UNKNOWN: Application Gateway inventory unavailable", RULE_ID)
        return []
    timestamp = datetime.now(timezone.utc).isoformat()
    findings = []
    for gateway in gateways:
        if not waf_enabled(gateway):
            continue
        resource_id = getattr(gateway, "id", "") or ""
        sku_name = getattr(getattr(gateway, "sku", None), "name", "") or ""
        enabled = azure_client.get_waf_diagnostic_logging(resource_id, sku_name)
        if enabled is None:
            logger.warning("%s UNKNOWN for %s: diagnostic settings unavailable", RULE_ID, getattr(gateway, "name", ""))
            continue
        if enabled:
            continue
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
                    observed={"required_waf_log_categories": "Incomplete", "sku": sku_name},
                    expected={"sku_supported_waf_log_categories": "Enabled"},
                    source="Azure Monitor diagnostic settings",
                    timestamp=timestamp,
                    permissions=["Microsoft.Insights/diagnosticSettings/read"],
                ),
            }
        )
    return findings
