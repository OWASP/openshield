"""AZ-DB-004: SQL Server firewall allows all Azure services."""

from typing import Any, Dict, List

RULE_ID = "AZ-DB-004"
RULE_NAME = "SQL Server Firewall Allows All Azure Services"
SEVERITY = "HIGH"
CATEGORY = "Database"
FRAMEWORKS = {"CIS": "4.1.2", "NIST": "PR.AC-3", "ISO27001": "A.8.20", "SOC2": "CC6.6"}
DESCRIPTION = (
    "Azure SQL Server has the 'Allow access to Azure services' firewall setting "
    "enabled. This creates a firewall rule that permits any resource hosted in "
    "Azure — including services from other tenants — to connect to the SQL Server. "
    "This significantly increases the attack surface and can allow unauthorised "
    "access from compromised or malicious Azure-hosted services."
)
REMEDIATION = (
    "Disable the 'Allow access to Azure services' setting on the SQL Server "
    "firewall. Instead, add explicit firewall rules for specific trusted IP "
    "ranges or use private endpoints to restrict access to known sources only."
)
PLAYBOOK = "playbooks/cli/fix_az_db_004.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return a list of findings. Return [] if no issues are found."""
    findings: List[Dict[str, Any]] = []

    for server in azure_client.get_sql_servers():
        parsed = azure_client.parse_resource_id(server.id)
        resource_group = parsed["resource_group"]
        server_name = parsed["name"]

        firewall_rules = azure_client.get_sql_server_firewall_rules(resource_group, server_name)

        for rule in firewall_rules:
            start_ip = getattr(rule, "start_ip_address", "")
            end_ip = getattr(rule, "end_ip_address", "")

            # detecting an open firewall range, not a socket bind
            if start_ip == "0.0.0.0" and end_ip == "0.0.0.0":  # nosec B104
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "category": CATEGORY,
                        "resource_id": server.id,
                        "resource_name": server_name,
                        "resource_type": "Microsoft.Sql/servers",
                        "description": DESCRIPTION,
                        "remediation": REMEDIATION,
                        "playbook": PLAYBOOK,
                        "frameworks": FRAMEWORKS,
                        "metadata": {"resource_group": resource_group},
                    }
                )
                break

    return findings
