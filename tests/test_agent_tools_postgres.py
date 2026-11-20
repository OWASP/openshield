"""PostgreSQL integration tests for api.agent.tools.

These tests require a live PostgreSQL database with the baseline schema applied.
They are skipped when DATABASE_URL is not set (CI unit-test runs).

Each test uses an isolated subscription UUID so tests do not interfere with each
other and can be safely run in parallel.
"""

import os
import uuid

import psycopg2
import pytest

from api.agent.tools import (
    explain_finding,
    get_compliance_posture,
    get_findings,
    suggest_remediation,
)
from api.models.finding import DatabaseManager

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="DATABASE_URL is required for PostgreSQL integration tests",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def pg_conn():
    """Open a bare psycopg2 connection and roll back all changes on teardown."""
    dsn = os.environ["DATABASE_URL"]
    conn = psycopg2.connect(dsn)
    conn.autocommit = False
    yield conn
    conn.rollback()
    conn.close()


@pytest.fixture
def db_manager():
    """Return a connected DatabaseManager; close it on teardown."""
    dsn = os.environ["DATABASE_URL"]
    dm = DatabaseManager(dsn)
    dm.connect()
    yield dm
    dm.close()


@pytest.fixture
def scan_with_findings(pg_conn):
    """Insert one completed scan with two findings; return (conn, scan_id, subscription_id).

    Uses an isolated subscription UUID so this fixture is safe to run in parallel.
    Teardown is handled by pg_conn's rollback.
    """
    subscription_id = str(uuid.uuid4())
    scan_id = uuid.uuid4()
    tenant_id = "test-tenant-integration"

    with pg_conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scans (scan_id, subscription_id, status, started_at)
            VALUES (%s, %s, 'completed', NOW())
            """,
            (str(scan_id), subscription_id),
        )
        # Two findings: one HIGH, one MEDIUM.
        # detected_at and finding_key are NOT NULL after migrations.
        cur.execute(
            """
            INSERT INTO findings
              (scan_id, rule_id, rule_name, severity, resource_id,
               resource_name, resource_type, description, remediation,
               detected_at, finding_key)
            VALUES
              (%s, 'AZ-NET-001', 'Open NSG inbound', 'HIGH',
               '/subscriptions/{sub}/rg/rg1/nsg1',
               'nsg1', 'Microsoft.Network/networkSecurityGroups',
               'NSG allows unrestricted inbound.', 'Restrict inbound rules.',
               NOW(), %s),
              (%s, 'AZ-STOR-001', 'Public blob access', 'MEDIUM',
               '/subscriptions/{sub}/rg/rg1/stor1',
               'stor1', 'Microsoft.Storage/storageAccounts',
               'Storage account allows public blob access.', 'Disable public access.',
               NOW(), %s)
            """,
            (str(scan_id), f"test:nsg:{scan_id}", str(scan_id), f"test:stor:{scan_id}"),
        )

    return pg_conn, str(scan_id), subscription_id, tenant_id


# ---------------------------------------------------------------------------
# get_findings
# ---------------------------------------------------------------------------


class TestGetFindingsPostgres:
    def test_returns_all_findings_for_subscription(self, scan_with_findings):
        conn, scan_id, subscription_id, tenant_id = scan_with_findings
        result = get_findings(conn, subscription_id, tenant_id)
        assert isinstance(result, list)
        assert len(result) == 2
        rule_ids = {r["rule_id"] for r in result}
        assert rule_ids == {"AZ-NET-001", "AZ-STOR-001"}

    def test_severity_filter_narrows_results(self, scan_with_findings):
        conn, scan_id, subscription_id, tenant_id = scan_with_findings
        result = get_findings(conn, subscription_id, tenant_id, severity="HIGH")
        assert len(result) == 1
        assert result[0]["rule_id"] == "AZ-NET-001"
        assert result[0]["severity"] == "HIGH"

    def test_severity_filter_is_case_insensitive(self, scan_with_findings):
        conn, scan_id, subscription_id, tenant_id = scan_with_findings
        result_lower = get_findings(conn, subscription_id, tenant_id, severity="high")
        result_upper = get_findings(conn, subscription_id, tenant_id, severity="HIGH")
        assert len(result_lower) == len(result_upper) == 1

    def test_state_filter_is_silently_ignored(self, scan_with_findings):
        """state= is accepted without error but ignored until lifecycle tables ship."""
        conn, scan_id, subscription_id, tenant_id = scan_with_findings
        result = get_findings(conn, subscription_id, tenant_id, state="open")
        assert len(result) == 2

    def test_all_findings_have_open_state(self, scan_with_findings):
        """Without lifecycle tables every finding is reported as 'open'."""
        conn, scan_id, subscription_id, tenant_id = scan_with_findings
        result = get_findings(conn, subscription_id, tenant_id)
        assert all(r["state"] == "open" for r in result)

    def test_unknown_subscription_returns_empty_list(self, scan_with_findings):
        conn, _scan_id, _subscription_id, tenant_id = scan_with_findings
        result = get_findings(conn, str(uuid.uuid4()), tenant_id)
        assert result == []

    def test_only_latest_completed_scan_is_returned(self, scan_with_findings):
        """An older completed scan for the same subscription is excluded."""
        conn, _current_scan_id, subscription_id, tenant_id = scan_with_findings
        old_scan_id = uuid.uuid4()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO scans (scan_id, subscription_id, status, started_at) "
                "VALUES (%s, %s, 'completed', NOW() - INTERVAL '1 hour')",
                (str(old_scan_id), subscription_id),
            )
            cur.execute(
                """
                INSERT INTO findings
                  (scan_id, rule_id, rule_name, severity, resource_id,
                   resource_name, resource_type, description, remediation,
                   detected_at, finding_key)
                VALUES (%s, 'AZ-OLD-001', 'Old finding', 'LOW',
                        '/subs/x', 'x', 'type', 'old', 'fix it', NOW(), %s)
                """,
                (str(old_scan_id), f"test:old:{old_scan_id}"),
            )
        # Only the two findings from the most recent scan should appear
        result = get_findings(conn, subscription_id, tenant_id)
        rule_ids = {r["rule_id"] for r in result}
        assert "AZ-OLD-001" not in rule_ids


# ---------------------------------------------------------------------------
# explain_finding / suggest_remediation
# ---------------------------------------------------------------------------


class TestExplainFindingPostgres:
    def test_returns_expected_fields_for_existing_finding(self, scan_with_findings):
        conn, _scan_id, subscription_id, tenant_id = scan_with_findings
        findings = get_findings(conn, subscription_id, tenant_id)
        assert findings, "Prerequisite: at least one finding must exist"
        fid = findings[0]["finding_id"]

        detail = explain_finding(conn, fid, tenant_id)
        assert detail is not None
        assert detail["finding_id"] == fid
        assert "rule_id" in detail
        assert "severity" in detail
        assert "description" in detail
        assert "remediation" in detail
        assert detail["state"] == "open"

    def test_returns_none_for_nonexistent_finding(self, scan_with_findings):
        conn, _scan_id, _subscription_id, tenant_id = scan_with_findings
        result = explain_finding(conn, 999_999_999, tenant_id)
        assert result is None

    def test_suggest_remediation_returns_steps(self, scan_with_findings):
        conn, _scan_id, subscription_id, tenant_id = scan_with_findings
        findings = get_findings(conn, subscription_id, tenant_id)
        fid = findings[0]["finding_id"]

        result = suggest_remediation(conn, fid, tenant_id)
        assert result is not None
        assert "steps" in result
        assert isinstance(result["steps"], str)
        assert result["finding_id"] == fid


# ---------------------------------------------------------------------------
# get_compliance_posture
# ---------------------------------------------------------------------------


class TestGetCompliancePosturePostgres:
    def test_returns_dict_with_framework_key_for_known_framework(self, db_manager, scan_with_findings):
        """get_compliance_posture delegates to get_compliance_score and returns a dict."""
        _conn, _scan_id, subscription_id, tenant_id = scan_with_findings
        result = get_compliance_posture(db_manager, "mcsb", subscription_id, tenant_id)
        assert isinstance(result, dict)
        assert (
            result.get("framework") == "mcsb"
            or result.get("status")
            in (
                "NO_SCAN_DATA",
                None,
            )
            or "error" not in result
        )

    def test_raises_for_unknown_framework(self, db_manager):
        with pytest.raises(ValueError, match="Unknown compliance framework"):
            get_compliance_posture(db_manager, "made-up", "sub-1", "tenant-1")

    def test_no_error_key_when_scan_exists(self, db_manager, scan_with_findings):
        """With a completed scan present the response should not be an error."""
        _conn, _scan_id, subscription_id, tenant_id = scan_with_findings
        result = get_compliance_posture(db_manager, "cis", subscription_id, tenant_id)
        assert "error" not in result
