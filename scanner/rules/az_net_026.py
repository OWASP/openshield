"""AZ-NET-026: WAF lacks current managed rules or bot protection."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from scanner.rules._perimeter_common import REQUIRED_NETWORK_PERMISSIONS, metadata, policy_by_id, waf_enabled

RULE_ID = "AZ-NET-026"
RULE_NAME = "WAF Lacks Current Managed Rules or Bot Protection"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "N/A-NET-026", "NIST": "PR.PT-4", "ISO27001": "A.14.2.5", "SOC2": "CC6.6"}
DESCRIPTION = (
    "An Application Gateway WAF lacks both an approved current base managed rule set and Microsoft bot protection."
)
REMEDIATION = (
    "Associate a WAF policy using OWASP 3.2 or Microsoft Default Rule Set 2.1 or later, "
    "plus Microsoft Bot Manager Rule Set 1.0 or later."
)
PLAYBOOK = "playbooks/cli/fix_az_net_026.sh"
logger = logging.getLogger(__name__)


def _version_at_least(value: Any, minimum: tuple[int, int]) -> bool:
    try:
        parts = tuple(int(part) for part in str(value).split(".")[:2])
        return parts >= minimum
    except (TypeError, ValueError):
        return False


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
        if policy:
            rule_sets = getattr(getattr(policy, "managed_rules", None), "managed_rule_sets", None)
        else:
            inline = getattr(gateway, "web_application_firewall_configuration", None)
            rule_sets = [inline] if inline and getattr(inline, "rule_set_type", None) else None
        if rule_sets is None:
            logger.warning(
                "%s UNKNOWN for %s: managed rule inventory unavailable", RULE_ID, getattr(gateway, "name", "")
            )
            continue
        current_base = any(
            (
                str(getattr(item, "rule_set_type", "")).lower() == "owasp"
                and _version_at_least(getattr(item, "rule_set_version", ""), (3, 2))
            )
            or (
                str(getattr(item, "rule_set_type", "")).lower() == "microsoft_defaultruleset"
                and _version_at_least(getattr(item, "rule_set_version", ""), (2, 1))
            )
            for item in rule_sets
        )
        bot = any(
            str(getattr(item, "rule_set_type", "")).lower() == "microsoft_botmanagerruleset"
            and _version_at_least(getattr(item, "rule_set_version", ""), (1, 0))
            for item in rule_sets
        )
        if current_base and bot:
            continue
        resource_id = getattr(gateway, "id", "") or ""
        observed_sets = [
            {"type": getattr(item, "rule_set_type", ""), "version": getattr(item, "rule_set_version", "")}
            for item in rule_sets
        ]
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
                    observed={"managed_rule_sets": observed_sets, "current_base": current_base, "bot_protection": bot},
                    expected={"current_base": True, "bot_protection": True},
                    source="Azure Resource Manager: WAF managed rules",
                    timestamp=timestamp,
                    permissions=REQUIRED_NETWORK_PERMISSIONS,
                ),
            }
        )
    return findings
