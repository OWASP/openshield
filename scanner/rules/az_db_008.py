"""AZ-DB-008: Azure SQL Server does not enforce a minimum TLS version of 1.2."""

from typing import Any, Dict, List

from scanner.evaluation import EvaluationStatus, RuleEvaluation, subscription_scope_id

RULE_ID = "AZ-DB-008"
RULE_NAME = "Azure SQL Server Minimum TLS Version Below 1.2"
SEVERITY = "HIGH"
CATEGORY = "Database"
FRAMEWORKS = {"CIS": "N/A-DB-008", "NIST": "PR.DS-2", "ISO27001": "A.10.1.1", "SOC2": "CC6.7"}
DESCRIPTION = (
    "The Azure SQL Server does not enforce a minimum TLS version of 1.2 or higher. "
    "Connections are still able to negotiate the deprecated TLS 1.0 or 1.1 protocols, "
    "or no minimum is set at all, leaving data in transit exposed to known protocol "
    "downgrade and interception weaknesses in those older versions."
)
REMEDIATION = (
    "Set the server's minimum TLS version to 1.2. "
    "Run: az sql server update --name <server-name> --resource-group <resource-group> "
    "--minimal-tls-version 1.2"
)
PLAYBOOK = "playbooks/cli/fix_az_db_008.sh"

# The Server model's minimal_tls_version is a free string, not an enum, and the
# real Azure API allows "None" (no minimum enforced) alongside "1.0"/"1.1"/"1.2"/
# "1.3" -- a missing attribute (None) must be treated the same as an explicit
# below-1.2 value, not skipped, since both mean TLS 1.2 is not being enforced.
_COMPLIANT_VERSIONS = {"1.2", "1.3"}


def _finding(azure_client: Any, server: Any, tls_version: Any) -> Dict[str, Any]:
    parsed = azure_client.parse_resource_id(server.id)
    return {
        "rule_id": RULE_ID,
        "rule_name": RULE_NAME,
        "severity": SEVERITY,
        "category": CATEGORY,
        "resource_id": server.id,
        "resource_name": server.name,
        "resource_type": "Microsoft.Sql/servers",
        "description": DESCRIPTION,
        "remediation": REMEDIATION,
        "playbook": PLAYBOOK,
        "frameworks": FRAMEWORKS,
        "metadata": {
            "resource_group": parsed.get("resource_group", ""),
            "location": getattr(server, "location", ""),
            "minimal_tls_version": tls_version or "not set",
        },
    }


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect Azure SQL Servers whose minimum TLS version is below 1.2 or unset."""
    findings: List[Dict[str, Any]] = []

    for server in azure_client.get_sql_servers():
        tls_version = getattr(server, "minimal_tls_version", None)
        if tls_version not in _COMPLIANT_VERSIONS:
            findings.append(_finding(azure_client, server, tls_version))

    return findings


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report coverage per server (PASS included), so an inventory that could
    not be read is recorded as UNKNOWN instead of reading as a clean scan."""
    servers = azure_client.get_sql_servers()
    if not servers:
        # AzureClient.get_sql_servers() returns [] both for a subscription with
        # no SQL servers and when the list call itself failed (authorization,
        # network, throttling), and scan() cannot tell them apart. UNKNOWN is
        # the conservative record: it never counts as a pass in compliance
        # scoring, whereas an empty findings list would look compliant.
        return [
            RuleEvaluation(
                rule_id=RULE_ID,
                resource_id=subscription_scope_id(subscription_id),
                resource_type="Microsoft.Sql/servers",
                status=EvaluationStatus.UNKNOWN,
                reason_code="INVENTORY_EMPTY_OR_UNAVAILABLE",
                reason=(
                    "No Azure SQL servers were returned; this is indistinguishable from a failed "
                    "list call (authorization, network or throttling), so coverage is unknown."
                ),
            )
        ]

    evaluations: List[RuleEvaluation] = []
    for server in servers:
        tls_version = getattr(server, "minimal_tls_version", None)
        if tls_version in _COMPLIANT_VERSIONS:
            evaluations.append(
                RuleEvaluation(
                    rule_id=RULE_ID,
                    resource_id=server.id,
                    resource_type="Microsoft.Sql/servers",
                    status=EvaluationStatus.PASS,
                )
            )
        else:
            evaluations.append(
                RuleEvaluation(
                    rule_id=RULE_ID,
                    resource_id=server.id,
                    resource_type="Microsoft.Sql/servers",
                    status=EvaluationStatus.FAIL,
                    finding=_finding(azure_client, server, tls_version),
                )
            )

    return evaluations
