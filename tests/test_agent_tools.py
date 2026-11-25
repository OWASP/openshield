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
    """Minimal psycopg2 connection stand-in.

    ``rows`` is used for every query. When ``get_findings`` is used with the
    new two-phase design (scan check + findings query), pass a non-empty rows
    list so that ``fetchone()`` returns a truthy scan_id on the first call and
    ``fetchall()`` returns findings on the second call.

    For tests that only need the scan-check to pass without caring about the
    finding rows, pass ``check_rows`` as a one-element list (e.g. ``[("scan-1",)]``).
    """

    def __init__(self, rows=None):
        self._cursor = _FakeCursor(rows)
        self.committed = False

    def cursor(self):
        return self._cursor

    def commit(self):
        self.committed = True

    def rollback(self):
        pass


# ---------------------------------------------------------------------------
# scan_subscription
# ---------------------------------------------------------------------------


class _FakeDM:
    """Minimal DatabaseManager stand-in exposing admit_scan and get_compliance_score."""

    def __init__(self, result=None, raises=None, compliance_result=None, compliance_raises=None):
        self._result = result
        self._raises = raises
        self._compliance_result = compliance_result
        self._compliance_raises = compliance_raises
        self.calls = []
        self.quotas = []
        self.compliance_calls: list = []

    def admit_scan(self, scan_id, subscription_id, *, idempotency_key=None, max_scans_per_hour=0):
        self.calls.append((scan_id, subscription_id))
        self.quotas.append(max_scans_per_hour)
        if self._raises is not None:
            raise self._raises
        return self._result

    def get_compliance_score(self, framework, subscription_id=None):
        self.compliance_calls.append((framework, subscription_id))
        if self._compliance_raises is not None:
            raise self._compliance_raises
        if self._compliance_result is not None:
            return self._compliance_result
        return {
            "framework": framework,
            "status": "NO_SCAN_DATA",
            "score_percent": None,
            "passed": None,
            "failed": None,
            "controls": [],
        }


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

    def test_honours_configured_hourly_quota(self, monkeypatch):
        """The env-configured hourly quota is forwarded to admit_scan (parity with the REST route)."""
        monkeypatch.setenv("OPENSHIELD_MAX_SCANS_PER_SUBSCRIPTION_PER_HOUR", "3")
        dm = _FakeDM(result=({"scan_id": "abc", "status": "pending"}, True))
        scan_subscription(dm, subscription_id="sub-1", tenant_id="tenant-1")
        assert dm.quotas == [3]

    def test_invalid_quota_env_disables_quota(self, monkeypatch):
        """A malformed quota env value falls back to 0 (no limit), never crashes."""
        monkeypatch.setenv("OPENSHIELD_MAX_SCANS_PER_SUBSCRIPTION_PER_HOUR", "not-a-number")
        dm = _FakeDM(result=({"scan_id": "abc", "status": "pending"}, True))
        scan_subscription(dm, subscription_id="sub-1", tenant_id="tenant-1")
        assert dm.quotas == [0]

    def test_quota_exceeded_is_not_masked(self, monkeypatch):
        """ScanQuotaExceeded keeps its specific message instead of a generic failure."""
        from api.models.finding import ScanQuotaExceeded

        monkeypatch.setenv("OPENSHIELD_MAX_SCANS_PER_SUBSCRIPTION_PER_HOUR", "1")
        dm = _FakeDM(raises=ScanQuotaExceeded("Configured hourly scan quota has been reached"))
        with pytest.raises(ScanQuotaExceeded, match="quota"):
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
        # Provide a non-empty rows list so the scan-existence check (fetchone)
        # returns a truthy scan_id; the same rows are reused for the findings
        # query (fetchall), which is acceptable for this param-checking test.
        scan_row = [("fake-scan-id",)]
        conn = _FakeConn(rows=scan_row)
        get_findings(
            conn,
            subscription_id="sub-1",
            tenant_id="tenant-1",
            severity="HIGH",
        )
        params = conn._cursor.executed_params
        assert "HIGH" in params

    def test_no_completed_scan_returns_status_dict(self):
        """get_findings returns a no_completed_scan dict when no scan exists for the subscription."""
        conn = _FakeConn(rows=[])
        result = get_findings(conn, subscription_id="sub-1", tenant_id="tenant-1")
        assert isinstance(result, dict)
        assert result["status"] == "no_completed_scan"
        assert "message" in result

    def test_state_filter_is_silently_ignored(self):
        """get_findings accepts state= without error but ignores it.

        Without lifecycle tables all findings are 'open'; passing state is a
        no-op until PR #326 ships.
        """
        # Provide a scan row so the check passes; the state filter is then applied.
        conn = _FakeConn(rows=[("fake-scan-id",)])
        result = get_findings(
            conn,
            subscription_id="sub-1",
            tenant_id="tenant-1",
            state="OPEN",
        )
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# get_compliance_posture
# ---------------------------------------------------------------------------


class TestGetCompliancePosture:
    def test_valid_framework_delegates_to_get_compliance_score(self):
        """get_compliance_posture calls DatabaseManager.get_compliance_score and returns its result."""
        expected = {
            "framework": "cis",
            "score_percent": 72.5,
            "passed": 29,
            "failed": 11,
            "controls": [],
        }
        dm = _FakeDM(compliance_result=expected)
        result = get_compliance_posture(
            dm,
            framework="cis",
            subscription_id="sub-1",
            tenant_id="tenant-1",
        )
        assert result == expected
        assert dm.compliance_calls == [("cis", "sub-1")]

    def test_raises_value_error_for_unknown_framework(self):
        """get_compliance_posture raises ValueError for an unrecognised framework."""
        dm = _FakeDM()
        with pytest.raises(ValueError, match="Unknown compliance framework"):
            get_compliance_posture(
                dm,
                framework="nist-made-up",
                subscription_id="sub-1",
                tenant_id="tenant-1",
            )

    def test_no_scan_data_returned_as_is(self):
        """get_compliance_posture passes NO_SCAN_DATA back unchanged."""
        dm = _FakeDM()
        result = get_compliance_posture(
            dm,
            framework="cis",
            subscription_id="sub-1",
            tenant_id="tenant-1",
        )
        assert result.get("status") == "NO_SCAN_DATA"
        assert result.get("framework") == "cis"

    def test_db_failure_returns_explicit_error_not_zeroed(self):
        """A failure in get_compliance_score must surface as an error, never a zeroed score."""
        dm = _FakeDM(compliance_raises=RuntimeError("db down"))
        result = get_compliance_posture(
            dm,
            framework="cis",
            subscription_id="sub-1",
            tenant_id="tenant-1",
        )
        assert result.get("error") == "db_error"
        assert result.get("framework") == "cis"
        assert "score" not in result

    def test_missing_get_compliance_score_method_returns_error(self):
        """A raw connection (no get_compliance_score) returns db_error, never crashes."""
        conn = _FakeConn(rows=[])
        result = get_compliance_posture(
            conn,
            framework="iso27001",
            subscription_id="sub-1",
            tenant_id="tenant-1",
        )
        assert result.get("error") == "db_error"
        assert result.get("framework") == "iso27001"


# ---------------------------------------------------------------------------
# get_attack_paths
# ---------------------------------------------------------------------------


class TestGetAttackPaths:
    def test_returns_not_available_status(self):
        """get_attack_paths returns a not_available dict until path traversal is deployed.

        An empty list would let the agent interpret zero results as "no attack paths
        found", which is misleading before the traversal feature is live.
        """
        conn = _FakeConn(rows=[])
        result = get_attack_paths(conn, scan_id="scan-1", tenant_id="tenant-1")
        assert isinstance(result, dict)
        assert result.get("status") == "not_available"
        assert "reason" in result


# ---------------------------------------------------------------------------
# explain_finding
# ---------------------------------------------------------------------------


class TestExplainFinding:
    def test_returns_none_when_db_returns_no_row(self):
        """explain_finding returns None when the finding does not exist."""
        conn = _FakeConn(rows=[])
        result = explain_finding(conn, finding_id=999, subscription_id="sub-1", tenant_id="tenant-1")
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
        result = explain_finding(conn, finding_id=42, subscription_id="sub-1", tenant_id="tenant-1")
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
        result = suggest_remediation(conn, finding_id=999, subscription_id="sub-1", tenant_id="tenant-1")
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
        result = suggest_remediation(conn, finding_id=7, subscription_id="sub-1", tenant_id="tenant-1")
        assert result is not None
        assert "steps" in result
        assert result["steps"] == "Assign a managed identity and remove inline credentials."
        assert result["finding_id"] == 7
        assert result["rule_id"] == "AZ-ID-001"
        assert result["resource_id"] == "/subs/sub-1/rg/rg1/vm-1"
