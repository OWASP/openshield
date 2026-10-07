"""AZ-NET-015: Public DNS zone exposes private infrastructure via RFC1918 IPs or internal hostnames."""

from typing import Any, Dict, List

RULE_ID = "AZ-NET-015"
RULE_NAME = "Public DNS Zone Exposes Internal Infrastructure Details"
SEVERITY = "MEDIUM"
CATEGORY = "Network"
FRAMEWORKS = {
    "CIS": "9.8",
    "NIST": "PR.AC-5",
    "ISO27001": "A.8.20",
    "SOC2": "CC6.6",
}
DESCRIPTION = (
    "A public DNS zone contains records that reference private RFC1918 IP addresses "
    "or hostnames that suggest internal infrastructure (such as admin, vpn, db, "
    "internal, or dev). Exposing private IPs or internal service names in public DNS "
    "assists attackers in mapping the organisation's internal network topology "
    "and identifying targets for further attack."
)
REMEDIATION = (
    "Review all A records in public DNS zones and remove or migrate any records that "
    "reference private RFC1918 IP addresses or expose internal service names. "
    "Internal services should be resolved using Azure Private DNS zones linked to "
    "the appropriate virtual networks, not public DNS."
)
PLAYBOOK = "playbooks/cli/fix_az_net_015.sh"

_INTERNAL_KEYWORDS = {
    "admin",
    "vpn",
    "db",
    "internal",
    "dev",
    "staging",
    "test",
    "corp",
    "intranet",
    "private",
    "mgmt",
    "management",
    "bastion",
    "jump",
}


def _is_rfc1918(ip: str) -> bool:
    """Return True if the IP address falls within an RFC1918 private range."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first, second = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return first == 10 or (first == 172 and 16 <= second <= 31) or (first == 192 and second == 168)


def _is_internal_hostname(name: str) -> bool:
    """Return True if the record name matches a known internal-service keyword."""
    name_lower = name.lower()
    return any(keyword in name_lower for keyword in _INTERNAL_KEYWORDS)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for zone in azure_client.get_dns_zones():
        zone_type = getattr(zone, "zone_type", "Public")
        if zone_type != "Public":
            continue
        parsed = azure_client.parse_resource_id(zone.id)
        resource_group = parsed["resource_group"]

        exposed_private_ips: List[str] = []
        internal_hostnames: List[str] = []

        for record_set in azure_client.get_dns_record_sets(resource_group, zone.name):
            record_name = getattr(record_set, "name", "")
            for a_rec in getattr(record_set, "a_records", []) or []:
                ip = getattr(a_rec, "ipv4_address", "")
                if ip and _is_rfc1918(ip):
                    exposed_private_ips.append(f"{record_name}: {ip}")
            if record_name and _is_internal_hostname(record_name):
                internal_hostnames.append(record_name)

        if exposed_private_ips or internal_hostnames:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": zone.id,
                    "resource_name": zone.name,
                    "resource_type": "Microsoft.Network/dnsZones",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": resource_group,
                        "zone_type": zone_type,
                        "exposed_private_ips": exposed_private_ips,
                        "internal_hostnames": internal_hostnames,
                    },
                }
            )
    return findings
