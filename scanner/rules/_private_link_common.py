"""Shared, evidence-rich helpers for Private Link rules."""

from ipaddress import ip_address
from typing import Any, Dict, Optional

EVIDENCE_SOURCE = "Azure Resource Manager: Microsoft.Network/privateEndpoints"
REQUIRED_PERMISSIONS = [
    "Microsoft.Network/privateEndpoints/read",
    "Microsoft.Network/privateEndpoints/privateDnsZoneGroups/read",
    "target PaaS resource/read",
]


def private_address(value: str) -> Optional[bool]:
    """Return whether an address is non-public; malformed values are unknown."""
    try:
        return ip_address(value).is_private
    except ValueError:
        return None


def evidence(item: Dict[str, Any], observed: Any, expected: Any) -> Dict[str, Any]:
    return {
        "resource_group": item.get("resource_group", ""),
        "location": item.get("location", ""),
        "target_resource_id": item.get("target_id", ""),
        "evidence_source": EVIDENCE_SOURCE,
        "collection_timestamp": item.get("collected_at", ""),
        "observed": observed,
        "expected": expected,
        "required_permissions": REQUIRED_PERMISSIONS,
        "confidence": "HIGH",
    }
