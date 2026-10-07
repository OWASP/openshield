"""AZ-SC-004: Azure Container Registry has no image retention or quarantine policy."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-SC-004"
RULE_NAME = "Container Registry Missing Retention or Quarantine Policy"
SEVERITY = "MEDIUM"
CATEGORY = "Supply Chain"
FRAMEWORKS = {"CIS": "N/A-SC-004", "NIST": "PR.IP-1", "ISO27001": "A.8.32", "SOC2": "CC7.1"}

DESCRIPTION = (
    "The Azure Container Registry has no retention policy for untagged manifests, so stale and "
    "orphaned images accumulate indefinitely, widening the pool of images that can be deployed. "
    "On Premium-tier registries that also lack a quarantine policy, a newly pushed image is "
    "pullable and deployable before any vulnerability scan has evaluated it."
)

REMEDIATION = (
    "Enable a retention policy to purge untagged manifests after a defined window: "
    "az acr config retention update --registry <registry> --status enabled --days 30. "
    "On Premium-tier registries, also enable the quarantine policy so pushed images are held "
    "until scanned."
)

PLAYBOOK = "playbooks/cli/fix_az_sc_004.sh"

logger = logging.getLogger(__name__)

_PREMIUM_TIER = "premium"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect Container Registries missing a retention policy, or (Premium only) a quarantine policy."""
    findings: List[Dict[str, Any]] = []

    registries = azure_client.get_container_registries()
    if registries is None:
        logger.warning("%s: container registries could not be enumerated", RULE_ID)
        return findings

    for registry in registries:
        props = getattr(registry, "properties", None)
        if props is None:
            continue

        sku = getattr(registry, "sku", None)
        tier = str(getattr(sku, "tier", "") or "").lower() if sku is not None else ""
        is_premium = tier == _PREMIUM_TIER

        policies = getattr(props, "policies", None)
        retention_status = None
        quarantine_status = None
        if policies is not None:
            retention = getattr(policies, "retention_policy", None)
            quarantine = getattr(policies, "quarantine_policy", None)
            retention_status = getattr(retention, "status", None) if retention is not None else None
            quarantine_status = getattr(quarantine, "status", None) if quarantine is not None else None

        retention_enabled = str(retention_status or "").lower() == "enabled"
        quarantine_enabled = str(quarantine_status or "").lower() == "enabled"

        # Quarantine is a Premium-only feature; a Basic/Standard registry can
        # never satisfy it, so only require it on Premium registries.
        is_missing = not retention_enabled or (is_premium and not quarantine_enabled)

        if is_missing:
            parsed = azure_client.parse_resource_id(getattr(registry, "id", ""))
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": getattr(registry, "id", ""),
                    "resource_name": getattr(registry, "name", ""),
                    "resource_type": "Microsoft.ContainerRegistry/registries",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": parsed.get("resource_group", ""),
                        "sku_tier": tier,
                        "retention_policy_enabled": retention_enabled,
                        "quarantine_policy_enabled": quarantine_enabled if is_premium else None,
                    },
                }
            )

    return findings
