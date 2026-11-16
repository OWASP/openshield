"""Unit tests for api.agent.tools using a fake psycopg2 connection."""

import pytest

from api.agent.tools import (
    explain_finding,
    get_attack_paths,
    get_compliance_posture,
    get_findings,
    scan_subscription,
    suggest_remediation,
)


# ---------------------------------------------------------------------------
# Fake psycopg2 connection / cursor
# ---------------------------------------------------------------------------


class _FakeCursor:
    """Minimal psycopg2 cursor stand-in."""

    def __init__(self, rows=None):
        self._rows = rows or []
        self.executed_sql = None
        self.executed_params = None

    def execute(self, sql, params=None):
        self.executed_sql = sql
        self.executed_params = params

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class _FakeConn:
    """Minimal psycopg2 connection stand-in."""

    def __init__(self, rows=None):
        self._cursor = _FakeCursor(rows)
        self.committed = False

    def cursor(self):
        return self._cursor

    def commit(self):
        self.committed = True


# ---------------------------------------------------------------------------
# scan_subscription
# ---------------------------------------------------------------------------


class _FakeDM:
    """Minimal DatabaseManager stand-in exposing only admit_scan."""

    def __init__(self, result=None, raises=None):
        self._result = result
        self._raises = raises
        self.calls = []

    def admit_scan(self, scan_id, subscription_id, *, idempotency_key=None, max_scans_per_hour=0):
        self.calls.append((scan_id, subscription_id))
        if self._raises is not None:
            raise self._raises
        return self._result


class TestScanSubscription:
    def test_uses_admission_path_for_new_scan(self):
        """A newly admitted scan is reported with created=True."""
        dm = _FakeDM(result=({"scan_id": "abc-123", "status": "pending"}, True))
        result = scan_subscription(dm, subscription_id="sub-1", tenant_id="tenant-1")
        assert result == {"scan_id": "abc-123", "status": "pending", "created": True}
        # admit_scan called once with the subscription under test.
        assert len(dm.calls) == 1
        assert dm.calls[0][1] == "sub-1"

    def test_reports_existing_scan_without_creating(self):
        """An already-active scan is returned with created=False, not duplicated."""
        dm = _FakeDM(result=({"scan_id": "old", "status": "running"}, False))
        result = scan_subscription(dm, subscription_id="sub-1", tenant_id="tenant-1")
        assert result == {"scan_id": "old", "status": "running", "created": False}

    def test_raises_runtime_error_when_admission_fails(self):
        """A failure in admit_scan surfaces as a RuntimeError, never a silent success."""
        dm = _FakeDM(raises=RuntimeError("db down"))
        with pytest.raises(RuntimeError):
            scan_subscription(dm, subscription_id="sub-1", tenant_id="tenant-1")


# ---------------------------------------------------------------------------
# get_findings
# ---------------------------------------------------------------------------


class TestGetFindings:
    def test_no_filters_returns_list(self):
        """get_findings with no optional filters returns a list of dicts."""
        rows = [(1, "AZ-NET-001", "/subs/sub-1/rg/rg1", "HIGH", "OPEN")]
        conn = _FakeConn(rows=rows)
        result = get_findings(conn, subscription_id="sub-1", tenant_id="tenant-1")
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["finding_id"] == 1
        assert result[0]["rule_id"] == "AZ-NET-001"

    def test_severity_filter_passes_correct_param(self):
        """get_findings with severity filter includes severity in the SQL params."""
        conn = _FakeConn(rows=[])
        get_findings(
            conn,
            subscription_id="sub-1",
            tenant_id="tenant-1",
            severity="HIGH",
        )
        params = conn._cursor.executed_params
        assert "HIGH" in params

    def test_state_filter_passes_correct_param(self):
        """get_findings with state filter includes state in the SQL params."""
        conn = _FakeConn(rows=[])
        get_findings(
            conn,
            subscription_id="sub-1",
            tenant_id="tenant-1",
            state="OPEN",
        )
        params = conn._cursor.executed_params
        assert "OPEN" in params


# ---------------------------------------------------------------------------
# get_compliance_posture
# ---------------------------------------------------------------------------


class TestGetCompliancePosture:
    def test_valid_framework_returns_expected_keys(self):
        """get_compliance_posture with a valid framework returns required keys."""
        row = (85.5, 42, 8, ["gap-1", "gap-2"])
        conn = _FakeConn(rows=[row])
        result = get_compliance_posture(
            conn,
            framework="mcsb",
            subscription_id="sub-1",
            tenant_id="tenant-1",
        )
        assert result["framework"] == "mcsb"
        assert result["score"] == 85.5
        assert result["pass_count"] == 42
        assert result["fail_count"] == 8
        assert result["gaps"] == ["gap-1", "gap-2"]

    def test_raises_value_error_for_unknown_framework(self):
        """get_compliance_posture raises ValueError for an unrecognised framework."""
        conn = _FakeConn(rows=[])
        with pytest.raises(ValueError, match="Unknown compliance framework"):
            get_compliance_posture(
                conn,
                framework="nist-made-up",
                subscription_id="sub-1",
                tenant_id="tenant-1",
            )

    def test_no_data_returns_zeroed_structure(self):
        """get_compliance_posture returns zeroed structure when no rows exist."""
        conn = _FakeConn(rows=[])
        result = get_compliance_posture(
            conn,
            framework="cis",
            subscription_id="sub-1",
            tenant_id="tenant-1",
        )
        assert result["score"] == 0.0
        assert result["pass_count"] == 0
        assert result["fail_count"] == 0
        assert result["gaps"] == []


# ---------------------------------------------------------------------------
# get_attack_paths
# ---------------------------------------------------------------------------


class TestGetAttackPaths:
    def test_returns_empty_list(self):
        """get_attack_paths is a stub and always returns an empty list."""
        conn = _FakeConn(rows=[])
        result = get_attack_paths(conn, scan_id="scan-1", tenant_id="tenant-1")
        assert result == []


# ---------------------------------------------------------------------------
# explain_finding
# ---------------------------------------------------------------------------


class TestExplainFinding:
    def test_returns_none_when_db_returns_no_row(self):
        """explain_finding returns None when the finding does not exist."""
        conn = _FakeConn(rows=[])
        result = explain_finding(conn, finding_id=999, tenant_id="tenant-1")
        assert result is None

    def test_returns_dict_with_expected_keys_when_row_exists(self):
        """explain_finding returns a dict with all required keys when row found."""
        row = (
            42,
            "AZ-STOR-001",
            "/subs/sub-1/rg/rg1/stor-1",
            "MEDIUM",
            "Storage account accessible publicly.",
            "Disable public access on storage account.",
            "OPEN",
        )
        conn = _FakeConn(rows=[row])
        result = explain_finding(conn, finding_id=42, tenant_id="tenant-1")
        assert result is not None
        assert result["finding_id"] == 42
        assert result["rule_id"] == "AZ-STOR-001"
        assert result["severity"] == "MEDIUM"
        assert result["description"] == "Storage account accessible publicly."
        assert result["remediation"] == "Disable public access on storage account."
        assert result["state"] == "OPEN"


# ---------------------------------------------------------------------------
# suggest_remediation
# ---------------------------------------------------------------------------


class TestSuggestRemediation:
    def test_returns_none_when_finding_not_found(self):
        """suggest_remediation returns None when the underlying finding is missing."""
        conn = _FakeConn(rows=[])
        result = suggest_remediation(conn, finding_id=999, tenant_id="tenant-1")
        assert result is None

    def test_returns_dict_with_steps_key_when_finding_exists(self):
        """suggest_remediation returns a dict with a steps key when finding found."""
        row = (
            7,
            "AZ-ID-001",
            "/subs/sub-1/rg/rg1/vm-1",
            "HIGH",
            "Identity misconfigured.",
            "Assign a managed identity and remove inline credentials.",
            "OPEN",
        )
        conn = _FakeConn(rows=[row])
        result = suggest_remediation(conn, finding_id=7, tenant_id="tenant-1")
        assert result is not None
        assert "steps" in result
        assert result["steps"] == "Assign a managed identity and remove inline credentials."
        assert result["finding_id"] == 7
        assert result["rule_id"] == "AZ-ID-001"
        assert result["resource_id"] == "/subs/sub-1/rg/rg1/vm-1"
