"""AZ-CACHE-001: managed cache is public or permits TLS below 1.2."""

import logging
from typing import Any, Dict, List

from scanner.rules._storage_common import policy_required

logger = logging.getLogger(__name__)

RULE_ID = "AZ-CACHE-001"
RULE_NAME = "Managed Cache Public or Non-TLS Access"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "N/A-CACHE-001", "NIST": "PR.AC-5", "ISO27001": "A.13.1.1", "SOC2": "CC6.6"}
DESCRIPTION = "An explicitly protected managed cache permits public network access or a minimum TLS version below 1.2."
REMEDIATION = "Disable public access and require TLS 1.2 or later for the managed cache."
PLAYBOOK = "playbooks/cli/fix_az_cache_001.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    getter = getattr(azure_client, "get_managed_caches", None)
    if getter is None:
        return findings
    caches = getter()
    if caches is None:
        logger.warning("%s: managed cache inventory unavailable; result is indeterminate", RULE_ID)
        return findings
    for cache in caches:
        if not policy_required(cache, "oshield:cache-private-tls-required"):
            continue
        public = getattr(cache, "public_network_access", None)
        tls = getattr(cache, "minimum_tls_version", None)
        public_enabled = public is not None and str(getattr(public, "value", public)).strip().lower() not in {
            "disabled",
            "false",
            "none",
        }
        tls_insecure = tls is not None and str(getattr(tls, "value", tls)).strip().lower() in {
            "1.0",
            "1.1",
            "tls1_0",
            "tls1_1",
        }
        if not public_enabled and not tls_insecure:
            continue
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": cache.id,
                "resource_name": cache.name,
                "resource_type": "Microsoft.Cache/Redis",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {"public_network_access": str(public), "minimum_tls_version": str(tls)},
            }
        )
    return findings
