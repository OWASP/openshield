"""AZ-NET-003: NSG allows unrestricted inbound on port 443."""

import logging
from typing import Any, Dict, List

from scanner.azure_client import enum_str

RULE_ID = "AZ-NET-003"
RULE_NAME = "NSG allows unrestricted inbound on port 443"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "9.3", "NIST": "SC-7", "ISO27001": "A.13.1.1"}

DESCRIPTION = (
    "A Network Security Group has an inbound rule allowing unrestricted access "
    "on port 443 from any source (0.0.0.0/0). While HTTPS traffic is encrypted, "
    "exposing port 443 to the entire internet unnecessarily increases the attack "
    "surface and can expose web services to automated scanning and exploitation attempts. "
    "Note: this finding is expected for intentionally public-facing web services. "
    "Review manually before remediating — do not auto-remediate without confirming "
    "the service is not meant to be publicly accessible."
)

REMEDIATION = (
    "Restrict the inbound rule on port 443 to known IP ranges or use an "
    "Application Gateway with WAF to front any public-facing HTTPS services. "
    "If the service must be public, ensure it is protected by DDoS Standard."
)

PLAYBOOK = "playbooks/cli/fix_az_net_003.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect NSGs with unrestricted inbound access on port 443."""
    findings: List[Dict[str, Any]] = []

    for nsg in azure_client.get_network_security_groups():
        for rule in getattr(nsg, "security_rules", []) or []:
            direction = enum_str(getattr(rule, "direction", None))
            access = enum_str(getattr(rule, "access", None))

            allowed_sources = {
                "*",
                "0.0.0.0/0",
                "internet",
                "any",
            }

            # Azure can expose the source as either a single prefix
            # or a list of prefixes.
            single_prefix = enum_str(getattr(rule, "source_address_prefix", None))

            plural_prefixes = getattr(rule, "source_address_prefixes", None) or []

            matched_plural_prefix = next(
                (prefix for prefix in plural_prefixes if enum_str(prefix).lower() in allowed_sources),
                None,
            )

            source_matches = single_prefix.lower() in allowed_sources or matched_plural_prefix is not None

            # Azure can expose the destination port as either a single
            # port/range or a list of ports/ranges.
            destination_port_range = enum_str(getattr(rule, "destination_port_range", None))

            destination_port_ranges = getattr(rule, "destination_port_ranges", None) or []

            destination_port_ranges = [enum_str(port) for port in destination_port_ranges]

            port_matches = destination_port_range in ("443", "*") or any(
                port in ("443", "*") for port in destination_port_ranges
            )

            if direction.lower() == "inbound" and access.lower() == "allow" and source_matches and port_matches:
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "category": CATEGORY,
                        "resource_id": getattr(nsg, "id", ""),
                        "resource_name": getattr(nsg, "name", ""),
                        "resource_type": "Microsoft.Network/networkSecurityGroups",
                        "description": DESCRIPTION,
                        "remediation": REMEDIATION,
                        "playbook": PLAYBOOK,
                        "frameworks": FRAMEWORKS,
                        "metadata": {
                            "rule_name": getattr(rule, "name", ""),
                            "source_prefix": (single_prefix if single_prefix.lower() in allowed_sources else ""),
                            "matched_source_address_prefix": matched_plural_prefix,
                        },
                    }
                )
                break

    return findings
