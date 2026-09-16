"""AZ-NET-027: Internet-facing Application Gateway lacks WAF rate limiting."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from scanner.rules._perimeter_common import (
    REQUIRED_NETWORK_PERMISSIONS,
    metadata,
    policy_by_id,
    public_gateway,
    waf_enabled,
)

RULE_ID = "AZ-NET-027"
RULE_NAME = "Internet-Facing Application Gateway Lacks Approved Rate Limiting"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "N/A-NET-027", "NIST": "PR.PT-4", "ISO27001": "A.13.1.1", "SOC2": "CC6.6"}
DESCRIPTION = "A public Application Gateway has no enabled RateLimitRule in its associated WAF policy."
REMEDIATION = (
    "Associate a WAF policy and add an enabled RateLimitRule with thresholds "
    "and grouping appropriate to the application."
)
PLAYBOOK = "playbooks/cli/fix_az_net_027.sh"
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
        if not public_gateway(gateway) or not waf_enabled(gateway):
            continue
        policy_id = getattr(getattr(gateway, "firewall_policy", None), "id", "") or ""
        policy = indexed.get(policy_id.lower())
        rules = getattr(policy, "custom_rules", None) if policy else []
        rate_rules = [rule for rule in (rules or []) if str(getattr(rule, "rule_type", "")).lower() == "ratelimitrule"]
        states = [getattr(rule, "state", None) for rule in rate_rules]
        normalized_states = [str(getattr(state, "value", state)).lower() for state in states if state is not None]
        if "enabled" in normalized_states:
            continue
        if rate_rules and (
            len(normalized_states) != len(states) or any(state != "disabled" for state in normalized_states)
        ):
            logger.warning(
                "%s UNKNOWN for %s: rate-limit rule state missing or unrecognized",
                RULE_ID,
                getattr(gateway, "name", ""),
            )
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
                    observed={"enabled_rate_limit_rules": 0},
                    expected={"enabled_rate_limit_rules": ">=1"},
                    source="Azure Resource Manager: WAF custom rules",
                    timestamp=timestamp,
                    permissions=REQUIRED_NETWORK_PERMISSIONS,
                ),
            }
        )
    return findings
