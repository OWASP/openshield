"""Tests proving that a clean (zero-finding) completed scan is shown by posture
endpoints instead of falling back to stale data from an older scan."""

from unittest.mock import MagicMock, patch

from api.models.finding import DatabaseManager


# ── helpers ──────────────────────────────────────────────────────────────────


def _db() -> DatabaseManager:
    """Return a DatabaseManager with a mock DSN (no real connection used)."""
    db = DatabaseManager.__new__(DatabaseManager)
    db.dsn = "postgresql://mock/mock"
    db.conn = None
    return db


def _mock_cursor(rows, evaluation_rows=None):
    """Return a context-manager cursor mock that yields *rows* on fetchall().

    get_compliance_score() issues two SELECT/fetchall pairs (findings, then
    rule_evaluations); pass *evaluation_rows* to give the second call its own
    result instead of reusing *rows*.
    """
    cur = MagicMock()
    cur.__enter__ = lambda s: s
    cur.__exit__ = MagicMock(return_value=False)
    if evaluation_rows is not None:
        cur.fetchall.side_effect = [rows, evaluation_rows]
    else:
        cur.fetchall.return_value = rows
    cur.fetchone.return_value = rows[0] if rows else None
    return cur


# ── get_findings ──────────────────────────────────────────────────────────────


def test_get_findings_uses_completed_status_not_total_findings():
    """get_findings() must filter on status='completed', not total_findings > 0."""
    db = _db()
    conn = MagicMock()
    cur = _mock_cursor([])
    conn.cursor.return_value = cur

    with patch.object(db, "_get_conn", return_value=conn):
        db.get_findings()

    executed_sql = conn.cursor.return_value.execute.call_args[0][0]
    assert "status = 'completed'" in executed_sql
    assert "total_findings" not in executed_sql


def test_get_findings_clean_scan_returns_empty_list():
    """When the latest scan has no findings, get_findings() returns []."""
    db = _db()
    conn = MagicMock()
    cur = _mock_cursor([])
    conn.cursor.return_value = cur

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_findings()

    assert result == []


# ── get_score ─────────────────────────────────────────────────────────────────


def test_get_score_uses_completed_status():
    """get_score() must scope to status='completed', not total_findings > 0."""
    db = _db()
    conn = MagicMock()
    cur = _mock_cursor([])
    conn.cursor.return_value = cur

    with patch.object(db, "_get_conn", return_value=conn):
        db.get_score()

    executed_sql = conn.cursor.return_value.execute.call_args[0][0]
    assert "status = 'completed'" in executed_sql
    assert "total_findings" not in executed_sql


def test_get_score_is_100_after_clean_scan():
    """A clean scan (no findings) must yield a perfect score of 100."""
    db = _db()
    conn = MagicMock()
    cur = _mock_cursor([])
    conn.cursor.return_value = cur

    with patch.object(db, "_get_conn", return_value=conn):
        score = db.get_score()

    assert score == 100


def test_get_score_does_not_include_old_scan_findings():
    """After a clean scan, old HIGH findings must not deduct points."""
    db = _db()
    conn = MagicMock()
    cur = _mock_cursor([])
    conn.cursor.return_value = cur

    with patch.object(db, "_get_conn", return_value=conn):
        score = db.get_score()

    assert score == 100


# ── get_compliance_score ──────────────────────────────────────────────────────


def test_get_compliance_score_scopes_to_latest_scan():
    """get_compliance_score() must only look at findings from the latest completed
    scan, not the entire findings table."""
    db = _db()
    conn = MagicMock()
    cur = _mock_cursor([])
    conn.cursor.return_value = cur

    with patch.object(db, "_get_conn", return_value=conn):
        import json

        fake_framework = json.dumps(
            {
                "framework": "Test",
                "version": "1.0",
                "controls": {"AZ-STOR-001": {"control_id": "3.1", "control_name": "Test control"}},
            }
        )
        import io

        with patch("builtins.open", return_value=io.StringIO(fake_framework)):
            from pathlib import Path

            with patch.object(Path, "exists", return_value=True):
                db.get_compliance_score("cis")

    executed_sql = conn.cursor.return_value.execute.call_args[0][0]
    assert "status = 'completed'" in executed_sql
    assert "total_findings" not in executed_sql


def test_get_compliance_score_all_pass_after_clean_scan():
    """All controls show PASS when the latest scan recorded a PASS evaluation
    for every rule and produced no findings."""
    db = _db()
    conn = MagicMock()
    cur = _mock_cursor(
        [],
        evaluation_rows=[("AZ-STOR-001", "PASS"), ("AZ-NET-001", "PASS")],
    )
    conn.cursor.return_value = cur

    import json
    import io
    from pathlib import Path

    fake_framework = json.dumps(
        {
            "framework": "CIS Azure",
            "version": "2.0",
            "controls": {
                "AZ-STOR-001": {"control_id": "3.1", "control_name": "No public blobs"},
                "AZ-NET-001": {"control_id": "6.1", "control_name": "No unrestricted SSH"},
            },
        }
    )

    with patch.object(db, "_get_conn", return_value=conn):
        with patch("builtins.open", return_value=io.StringIO(fake_framework)):
            with patch.object(Path, "exists", return_value=True):
                result = db.get_compliance_score("cis")

    assert result["passed"] == 2
    assert result["failed"] == 0
    assert result["score_percent"] == 100
    statuses = {c["rule_id"]: c["status"] for c in result["controls"]}
    assert statuses["AZ-STOR-001"] == "PASS"
    assert statuses["AZ-NET-001"] == "PASS"


def test_get_compliance_score_no_evaluation_rows_is_unknown_not_pass():
    """A clean (zero-finding) scan with no rule_evaluations rows at all — e.g.
    a scan that predates #263, or a rule that was never evaluated — must
    report UNKNOWN, never silently default to PASS (the bug #263 fixes)."""
    db = _db()
    conn = MagicMock()
    cur = _mock_cursor([], evaluation_rows=[])
    conn.cursor.return_value = cur

    import json
    import io
    from pathlib import Path

    fake_framework = json.dumps(
        {
            "framework": "CIS Azure",
            "version": "2.0",
            "controls": {
                "AZ-STOR-001": {"control_id": "3.1", "control_name": "No public blobs"},
            },
        }
    )

    with patch.object(db, "_get_conn", return_value=conn):
        with patch("builtins.open", return_value=io.StringIO(fake_framework)):
            with patch.object(Path, "exists", return_value=True):
                result = db.get_compliance_score("cis")

    assert result["controls"][0]["status"] == "UNKNOWN"
    assert result["passed"] == 0
    assert result["unknown"] == 1
    assert result["score_percent"] == 0


def test_get_compliance_score_remediated_rule_shows_pass():
    """A rule that failed in scan-1 but recorded a PASS evaluation in scan-2
    (clean, remediated) must show PASS."""
    db = _db()
    conn = MagicMock()
    cur = _mock_cursor([], evaluation_rows=[("AZ-STOR-001", "PASS")])
    conn.cursor.return_value = cur

    import json
    import io
    from pathlib import Path

    fake_framework = json.dumps(
        {
            "framework": "CIS Azure",
            "version": "2.0",
            "controls": {
                "AZ-STOR-001": {"control_id": "3.1", "control_name": "No public blobs"},
            },
        }
    )

    with patch.object(db, "_get_conn", return_value=conn):
        with patch("builtins.open", return_value=io.StringIO(fake_framework)):
            with patch.object(Path, "exists", return_value=True):
                result = db.get_compliance_score("cis")

    assert result["controls"][0]["status"] == "PASS"


def test_get_compliance_score_reports_worst_critical_failure_without_inventing_pass_severity():
    db = _db()
    conn = MagicMock()
    cur = _mock_cursor(
        [
            ("AZ-STOR-001", "HIGH", "Storage", 1),
            ("AZ-STOR-001", "CRITICAL", "Storage", 2),
        ],
        evaluation_rows=[("AZ-STOR-001", "FAIL"), ("AZ-NET-001", "PASS")],
    )
    conn.cursor.return_value = cur

    import io
    import json
    from pathlib import Path

    fake_framework = json.dumps(
        {
            "framework": "CIS Azure",
            "version": "2.0",
            "controls": {
                "AZ-STOR-001": {"control_id": "3.1", "control_name": "No public blobs"},
                "AZ-NET-001": {"control_id": "6.1", "control_name": "No unrestricted SSH"},
            },
        }
    )

    with patch.object(db, "_get_conn", return_value=conn):
        with patch("builtins.open", return_value=io.StringIO(fake_framework)):
            with patch.object(Path, "exists", return_value=True):
                result = db.get_compliance_score("cis")

    controls = {control["rule_id"]: control for control in result["controls"]}
    assert controls["AZ-STOR-001"] == {
        "rule_id": "AZ-STOR-001",
        "control_id": "3.1",
        "control_name": "No public blobs",
        "status": "FAIL",
        "severity": "CRITICAL",
        "category": "Storage",
        "resources": 3,
    }
    assert controls["AZ-NET-001"]["status"] == "PASS"
    assert controls["AZ-NET-001"]["severity"] is None
