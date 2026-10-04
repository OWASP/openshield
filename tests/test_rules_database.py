"""Rule regression tests for the database rules AZ-DB-001 .. AZ-DB-004."""

import pytest

import scanner.rules.az_db_001 as az_db_001
import scanner.rules.az_db_002 as az_db_002
import scanner.rules.az_db_003 as az_db_003
import scanner.rules.az_db_004 as az_db_004
import scanner.rules.az_db_008 as az_db_008
from scanner.evaluation import EvaluationStatus
from tests.helpers.mock_azure import make_resource

try:
    from azure.mgmt.sql.models import BlobAuditingPolicyState, ServerBlobAuditingPolicy

    _AZURE_SQL_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when SDK isn't installed
    _AZURE_SQL_SDK_AVAILABLE = False

_REQUIRED_FIELDS = {
    "rule_id",
    "rule_name",
    "severity",
    "category",
    "resource_id",
    "resource_name",
    "resource_type",
    "description",
    "remediation",
    "playbook",
    "frameworks",
    "metadata",
}

_SUB = "00000000-0000-0000-0000-000000000001"
_RG = "rg-test"


def _sql_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Sql/servers/{name}"


def _firewall_rule(name, start_ip, end_ip):
    return make_resource(
        name=name,
        start_ip_address=start_ip,
        end_ip_address=end_ip,
    )


def test_db_004_compliant_returns_no_findings(mock_azure, subscription_id):
    """A SQL Server with no AllowAzureServices rule must produce no findings."""
    server = make_resource(id=_sql_id("sql-restricted"), name="sql-restricted")
    rule = _firewall_rule("AllowSpecificIP", "203.0.113.10", "203.0.113.10")
    mock_azure.set_sql_servers([server])
    mock_azure.set_sql_server_firewall_rules(_RG, "sql-restricted", [rule])
    findings = az_db_004.scan(mock_azure, subscription_id)
    assert findings == []


def test_db_004_noncompliant_returns_one_finding(mock_azure, subscription_id):
    """A SQL Server with AllowAllWindowsAzureIps rule must produce exactly one finding."""
    server = make_resource(id=_sql_id("sql-open"), name="sql-open")
    allow_azure = _firewall_rule("AllowAllWindowsAzureIps", "0.0.0.0", "0.0.0.0")
    mock_azure.set_sql_servers([server])
    mock_azure.set_sql_server_firewall_rules(_RG, "sql-open", [allow_azure])
    findings = az_db_004.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["rule_id"] == "AZ-DB-004"
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "Database"
    assert finding["resource_name"] == "sql-open"
    assert finding["metadata"]["resource_group"] == _RG


def test_db_004_no_firewall_rules_returns_no_findings(mock_azure, subscription_id):
    """A SQL Server with no firewall rules must produce no findings."""
    server = make_resource(id=_sql_id("sql-no-rules"), name="sql-no-rules")
    mock_azure.set_sql_servers([server])
    mock_azure.set_sql_server_firewall_rules(_RG, "sql-no-rules", [])
    findings = az_db_004.scan(mock_azure, subscription_id)
    assert findings == []


def test_db_002_disabled_policy_returns_one_finding(mock_azure, subscription_id):
    """A SQL Server with auditing explicitly disabled must produce one finding."""
    server = make_resource(id=_sql_id("sql-unaudited"), name="sql-unaudited")
    policy = make_resource(state="Disabled")
    mock_azure.set_sql_servers([server])
    mock_azure.set_sql_server_auditing_policy(_RG, "sql-unaudited", policy)
    findings = az_db_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-DB-002"


def test_db_002_enabled_policy_returns_no_findings(mock_azure, subscription_id):
    """A SQL Server with auditing enabled must produce no findings."""
    server = make_resource(id=_sql_id("sql-audited"), name="sql-audited")
    policy = make_resource(state="Enabled")
    mock_azure.set_sql_servers([server])
    mock_azure.set_sql_server_auditing_policy(_RG, "sql-audited", policy)
    findings = az_db_002.scan(mock_azure, subscription_id)
    assert findings == []


def test_db_002_api_failure_returns_indeterminate_finding(mock_azure, subscription_id):
    """TFT444 review: a failed policy lookup (None) must produce an
    indeterminate LOW finding (metadata.determination == "indeterminate"),
    matching the AZ-CMP-002 convention — not a silent skip and not a
    confirmed MEDIUM violation, since the actual auditing state is unknown.
    """
    server = make_resource(id=_sql_id("sql-api-failed"), name="sql-api-failed")
    mock_azure.set_sql_servers([server])
    mock_azure.set_sql_server_auditing_policy(_RG, "sql-api-failed", None)
    findings = az_db_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-DB-002"
    assert findings[0]["severity"] == "LOW"
    assert findings[0]["metadata"]["determination"] == "indeterminate"


def test_db_002_malformed_arm_id_does_not_raise(mock_azure, subscription_id):
    """COR-004: a server with a malformed ARM ID must not raise an error."""
    server = make_resource(id="not-a-valid-arm-id", name="sql-malformed")
    mock_azure.set_sql_servers([server])
    findings = az_db_002.scan(mock_azure, subscription_id)
    assert findings == []


def test_db_004_malformed_arm_id_does_not_raise_keyerror(mock_azure, subscription_id):
    """COR-004: az_db_004 indexes parsed["resource_group"] directly, so a
    malformed ARM ID with no resourceGroups segment previously raised a
    KeyError. parse_resource_id must always include the key.
    """
    server = make_resource(id="not-a-valid-arm-id", name="sql-malformed")
    mock_azure.set_sql_servers([server])
    mock_azure.set_sql_server_firewall_rules("", "sql-malformed", [])
    findings = az_db_004.scan(mock_azure, subscription_id)
    assert findings == []


@pytest.mark.skipif(not _AZURE_SQL_SDK_AVAILABLE, reason="azure-mgmt-sql not installed")
def test_db_002_disabled_policy_with_real_sdk_enum_returns_one_finding(mock_azure, subscription_id):
    """COR-003 (SDK model): a real ServerBlobAuditingPolicy with state as a
    BlobAuditingPolicyState.DISABLED enum, not a plain string, must still be
    flagged. str(enum) yields e.g. "BlobAuditingPolicyState.DISABLED" rather
    than "Disabled", so the rule must normalise via .value instead of naive str()."""
    server = make_resource(id=_sql_id("sql-unaudited-enum"), name="sql-unaudited-enum")
    policy = ServerBlobAuditingPolicy(state=BlobAuditingPolicyState.DISABLED)
    mock_azure.set_sql_servers([server])
    mock_azure.set_sql_server_auditing_policy(_RG, "sql-unaudited-enum", policy)
    findings = az_db_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["auditing_state"] == "Disabled"


@pytest.mark.skipif(not _AZURE_SQL_SDK_AVAILABLE, reason="azure-mgmt-sql not installed")
def test_db_002_enabled_policy_with_real_sdk_enum_returns_no_findings(mock_azure, subscription_id):
    """COR-003 (SDK model): a real enabled policy using the SDK enum must
    not be falsely flagged as disabled."""
    server = make_resource(id=_sql_id("sql-audited-enum"), name="sql-audited-enum")
    policy = ServerBlobAuditingPolicy(state=BlobAuditingPolicyState.ENABLED)
    mock_azure.set_sql_servers([server])
    mock_azure.set_sql_server_auditing_policy(_RG, "sql-audited-enum", policy)
    findings = az_db_002.scan(mock_azure, subscription_id)
    assert findings == []


def _pg_id(name, provider="Microsoft.DBforPostgreSQL/servers"):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/{provider}/{name}"


# ── AZ-DB-001: PostgreSQL single-server public network access ───────────────


def test_db_001_compliant_returns_no_findings(mock_azure, subscription_id):
    server = make_resource(
        id=_pg_id("pg-private"),
        name="pg-private",
        public_network_access="Disabled",
        location="eastus",
    )
    mock_azure.set_postgresql_servers([server])
    assert az_db_001.scan(mock_azure, subscription_id) == []


def test_db_001_noncompliant_returns_one_finding(mock_azure, subscription_id):
    server = make_resource(
        id=_pg_id("pg-public"),
        name="pg-public",
        public_network_access="Enabled",
        location="eastus",
    )
    mock_azure.set_postgresql_servers([server])
    findings = az_db_001.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-DB-001"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["resource_name"] == "pg-public"


# ── AZ-DB-002: Azure SQL server auditing disabled ───────────────────────────


def test_db_002_compliant_returns_no_findings(mock_azure, subscription_id):
    server = make_resource(id=_sql_id("sql-audited"), name="sql-audited")
    mock_azure.set_sql_servers([server])
    mock_azure.set_sql_server_auditing_policy(_RG, "sql-audited", make_resource(state="Enabled"))
    assert az_db_002.scan(mock_azure, subscription_id) == []


def test_db_002_noncompliant_returns_one_finding(mock_azure, subscription_id):
    server = make_resource(id=_sql_id("sql-unaudited"), name="sql-unaudited")
    mock_azure.set_sql_servers([server])
    mock_azure.set_sql_server_auditing_policy(_RG, "sql-unaudited", make_resource(state="Disabled"))
    findings = az_db_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-DB-002"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["resource_name"] == "sql-unaudited"


# ── AZ-DB-003: PostgreSQL flexible server SSL enforcement disabled ──────────


def test_db_003_compliant_returns_no_findings(mock_azure, subscription_id):
    server = make_resource(
        id=_pg_id("pgflex-ssl", "Microsoft.DBforPostgreSQL/flexibleServers"),
        name="pgflex-ssl",
        location="eastus",
    )
    mock_azure.set_postgresql_flexible_servers([server])
    mock_azure.set_postgresql_flexible_server_parameters(
        _RG,
        "pgflex-ssl",
        [make_resource(name="require_secure_transport", value="on")],
    )
    assert az_db_003.scan(mock_azure, subscription_id) == []


def test_db_003_noncompliant_returns_one_finding(mock_azure, subscription_id):
    server = make_resource(
        id=_pg_id("pgflex-nossl", "Microsoft.DBforPostgreSQL/flexibleServers"),
        name="pgflex-nossl",
        location="eastus",
    )
    mock_azure.set_postgresql_flexible_servers([server])
    mock_azure.set_postgresql_flexible_server_parameters(
        _RG,
        "pgflex-nossl",
        [make_resource(name="require_secure_transport", value="off")],
    )
    findings = az_db_003.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-DB-003"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["resource_name"] == "pgflex-nossl"


# ── AZ-DB-008: SQL server minimum TLS version below 1.2 ────────────────────


def test_db_008_compliant_tls_1_2_returns_no_findings(mock_azure, subscription_id):
    server = make_resource(id=_sql_id("sql-tls12"), name="sql-tls12", minimal_tls_version="1.2")
    mock_azure.set_sql_servers([server])
    assert az_db_008.scan(mock_azure, subscription_id) == []


def test_db_008_compliant_tls_1_3_returns_no_findings(mock_azure, subscription_id):
    server = make_resource(id=_sql_id("sql-tls13"), name="sql-tls13", minimal_tls_version="1.3")
    mock_azure.set_sql_servers([server])
    assert az_db_008.scan(mock_azure, subscription_id) == []


def test_db_008_noncompliant_tls_1_0_returns_one_finding(mock_azure, subscription_id):
    server = make_resource(id=_sql_id("sql-tls10"), name="sql-tls10", minimal_tls_version="1.0")
    mock_azure.set_sql_servers([server])
    findings = az_db_008.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["rule_id"] == "AZ-DB-008"
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "Database"
    assert finding["resource_name"] == "sql-tls10"
    assert finding["resource_type"] == "Microsoft.Sql/servers"
    assert finding["metadata"]["resource_group"] == _RG
    assert finding["metadata"]["minimal_tls_version"] == "1.0"


def test_db_008_noncompliant_tls_1_1_returns_one_finding(mock_azure, subscription_id):
    server = make_resource(id=_sql_id("sql-tls11"), name="sql-tls11", minimal_tls_version="1.1")
    mock_azure.set_sql_servers([server])
    findings = az_db_008.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-DB-008"


def test_db_008_noncompliant_explicit_none_returns_one_finding(mock_azure, subscription_id):
    """The real Azure API allows an explicit 'None' string meaning no minimum is enforced,
    distinct from the attribute simply being unset."""
    server = make_resource(id=_sql_id("sql-tls-none"), name="sql-tls-none", minimal_tls_version="None")
    mock_azure.set_sql_servers([server])
    findings = az_db_008.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["minimal_tls_version"] == "None"


def test_db_008_missing_attribute_defaults_to_noncompliant(mock_azure, subscription_id):
    """A server with no minimal_tls_version attribute at all must not be silently skipped."""
    server = make_resource(id=_sql_id("sql-tls-unset"), name="sql-tls-unset")
    mock_azure.set_sql_servers([server])
    findings = az_db_008.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["minimal_tls_version"] == "not set"


def test_db_008_evaluate_pass_and_fail_per_server(mock_azure, subscription_id):
    good = make_resource(id=_sql_id("sql-good"), name="sql-good", minimal_tls_version="1.2")
    bad = make_resource(id=_sql_id("sql-bad"), name="sql-bad", minimal_tls_version="1.0")
    mock_azure.set_sql_servers([good, bad])
    evaluations = az_db_008.evaluate(mock_azure, subscription_id)
    statuses = {e.resource_id: e.status for e in evaluations}
    assert statuses[_sql_id("sql-good")] == EvaluationStatus.PASS
    assert statuses[_sql_id("sql-bad")] == EvaluationStatus.FAIL
    failed = next(e for e in evaluations if e.status == EvaluationStatus.FAIL)
    assert failed.finding["rule_id"] == "AZ-DB-008"
    assert failed.finding["metadata"]["minimal_tls_version"] == "1.0"


def test_db_008_evaluate_unset_tls_is_fail_not_skipped(mock_azure, subscription_id):
    server = make_resource(id=_sql_id("sql-unset"), name="sql-unset")
    mock_azure.set_sql_servers([server])
    evaluations = az_db_008.evaluate(mock_azure, subscription_id)
    assert [e.status for e in evaluations] == [EvaluationStatus.FAIL]


def test_db_008_failed_or_empty_inventory_is_unknown_not_clean(mock_azure, subscription_id):
    """get_sql_servers() returns [] on an API failure as well as for a genuinely empty
    subscription. scan() alone would look like a clean result either way, so evaluate()
    must record UNKNOWN (never a PASS) for that case."""
    mock_azure.set_sql_servers([])
    evaluations = az_db_008.evaluate(mock_azure, subscription_id)
    assert len(evaluations) == 1
    assert evaluations[0].status == EvaluationStatus.UNKNOWN
    assert evaluations[0].reason_code == "INVENTORY_EMPTY_OR_UNAVAILABLE"
    assert evaluations[0].resource_id == f"/subscriptions/{subscription_id}"
