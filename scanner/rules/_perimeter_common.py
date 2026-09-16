"""Shared helpers for enterprise perimeter findings."""

from typing import Any, Dict

REQUIRED_NETWORK_PERMISSIONS = [
    "Microsoft.Network/applicationGateways/read",
    "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/read",
]


def resource_group(resource_id: str) -> str:
    parts = (resource_id or "").split("/")
    for index, part in enumerate(parts):
        if part.lower() == "resourcegroups" and index + 1 < len(parts):
            return parts[index + 1]
    return ""


def metadata(
    *,
    resource_id: str,
    observed: Any,
    expected: Any,
    source: str,
    timestamp: str,
    permissions: list[str],
) -> Dict[str, Any]:
    return {
        "resource_group": resource_group(resource_id),
        "evidence_source": source,
        "collection_timestamp": timestamp,
        "observed": observed,
        "expected": expected,
        "required_permissions": permissions,
        "confidence": "HIGH",
    }


def waf_enabled(gateway: Any) -> bool:
    config = getattr(gateway, "web_application_firewall_configuration", None)
    policy = getattr(gateway, "firewall_policy", None)
    return bool(getattr(config, "enabled", False) or getattr(policy, "id", ""))


def public_gateway(gateway: Any) -> bool:
    return any(
        getattr(getattr(config, "public_ip_address", None), "id", "")
        for config in (getattr(gateway, "frontend_ip_configurations", None) or [])
    )


def policy_by_id(policies: list[Any]) -> Dict[str, Any]:
    return {(getattr(policy, "id", "") or "").lower(): policy for policy in policies if getattr(policy, "id", "")}
