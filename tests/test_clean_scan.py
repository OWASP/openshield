"""Tests proving that a clean (zero-finding) completed scan is shown by posture
endpoints instead of falling back to stale data from an older scan."""

from unittest.mock import MagicMock, patch

from api.models.finding import DatabaseManager


# ── helpers ──────────────────────────────────────────────────────────────────


def _db() -> DatabaseManager:
    """Return a DatabaseManager with a mock DSN (no real connection used)."""
    db = DatabaseManager.__new__(DatabaseManager)
    db.dsn = "postgresql://mock/mock"
    db.subscription_id = "subscription-1"
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


def _mock_score_cursor(scan_row, severity_rows):
    """get_score() now issues two sequential queries on one cursor: a scan-
    existence check (fetchone) and, only if a scan was found, the severity
    breakdown (fetchall). A single rows list can no longer stand in for both,
    since a real completed scan with zero findings and no completed scan at
    all must be distinguishable."""
    cur = MagicMock()
    cur.__enter__ = lambda s: s
    cur.__exit__ = MagicMock(return_value=False)
    cur.fetchone.return_value = scan_row
    cur.fetchall.return_value = severity_rows
    return cur


def test_get_score_uses_completed_status():
    """get_score() must scope to status='completed', not total_findings > 0."""
    db = _db()
    conn = MagicMock()
    cur = _mock_score_cursor(None, [])
    conn.cursor.return_value = cur

    with patch.object(db, "_get_conn", return_value=conn):
        db.get_score()

    executed_sql = conn.cursor.return_value.execute.call_args[0][0]
    assert "status = 'completed'" in executed_sql
    assert conn.cursor.return_value.execute.call_args[0][1] == ("subscription-1",)
    assert "total_findings" not in executed_sql


def test_get_score_is_100_after_clean_scan():
    """A clean scan (no findings) must yield a perfect score of 100."""
    db = _db()
    conn = MagicMock()
    cur = _mock_score_cursor((1,), [])
    conn.cursor.return_value = cur

    with patch.object(db, "_get_conn", return_value=conn):
        score = db.get_score()

    assert score == {"status": "OK", "score": 100, "max_score": 100}


def test_get_score_does_not_include_old_scan_findings():
    """After a clean scan, old HIGH findings must not deduct points."""
    db = _db()
    conn = MagicMock()
    cur = _mock_score_cursor((1,), [])
    conn.cursor.return_value = cur

    with patch.object(db, "_get_conn", return_value=conn):
        score = db.get_score()

    assert score == {"status": "OK", "score": 100, "max_score": 100}


def test_get_score_no_completed_scan_returns_no_scan_data_not_a_pass():
    """No completed scan at all must never be reported as a perfect (or any)
    score - that would present the absence of evidence as a clean pass, the
    same class of bug fixed in get_compliance_score() for issue #302."""
    db = _db()
    conn = MagicMock()
    cur = _mock_score_cursor(None, [])
    conn.cursor.return_value = cur

    with patch.object(db, "_get_conn", return_value=conn):
        score = db.get_score()

    assert score["status"] == "NO_SCAN_DATA"
    assert score["score"] is None
    # Only the scan-existence check should have run - a NO_SCAN_DATA result
    # must not also execute (and discard) the findings/severity query.
    assert conn.cursor.return_value.execute.call_count == 1


# ── get_compliance_score ──────────────────────────────────────────────────────


def test_get_compliance_score_scopes_to_latest_scan():
    """get_compliance_score() must only look at findings from the latest completed
    scan, not the entire findings table."""
    db = _db()
    conn = MagicMock()
    cur = _mock_cursor([])
    cur.fetchone.return_value = {"scan_id": "scan-1", "compliance_mapping_snapshot": None}
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

    # get_compliance_score() issues two queries: first it resolves the latest
    # completed scan, then it looks up findings scoped to that resolved
    # scan_id — so "status = 'completed'" and the findings lookup are on
    # different statements, not one combined query.
    executed_statements = [call[0][0] for call in conn.cursor.return_value.execute.call_args_list]
    assert any("status = 'completed'" in sql for sql in executed_statements)
    findings_sql = executed_statements[-1]
    assert "FROM findings" in findings_sql
    assert "scan_id = %s" in findings_sql
    assert "total_findings" not in findings_sql


def test_get_compliance_score_all_pass_after_clean_scan():
    """All controls show PASS when the latest scan recorded a PASS evaluation
    for every rule and produced no findings."""
    db = _db()
    conn = MagicMock()
    cur = _mock_cursor(
        [],
        evaluation_rows=[("AZ-STOR-001", "PASS"), ("AZ-NET-001", "PASS")],
    )
    cur.fetchone.return_value = {"scan_id": "scan-1", "compliance_mapping_snapshot": None}
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
    cur.fetchone.return_value = {"scan_id": "scan-1", "compliance_mapping_snapshot": None}
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
    cur.fetchone.return_value = {"scan_id": "scan-2", "compliance_mapping_snapshot": None}
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
    # get_compliance_score() issues two queries on this connection: a
    # scan-existence check (RealDictCursor, fetchone) and, only once a scan
    # is confirmed to exist, the severity/category grouping below (a plain
    # cursor, fetchall - see the comment on that query for why it isn't
    # RealDictCursor too). conn.cursor(...) returns the same mock either way,
    # so fetchone must be configured with a real scan row, independently of
    # the grouped rows fetchall returns.
    cur = _mock_cursor(
        [
            ("AZ-STOR-001", "HIGH", "Storage", 1),
            ("AZ-STOR-001", "CRITICAL", "Storage", 2),
        ],
        evaluation_rows=[("AZ-STOR-001", "FAIL"), ("AZ-NET-001", "PASS")],
    )
    cur.fetchone.return_value = {"scan_id": "scan-1", "compliance_mapping_snapshot": None}
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
        # fake_framework's controls carry no evidence-schema fields, so
        # these all fall back to their defaults.
        "mapping_type": "supporting",
        "evidence_type": None,
        "primary_source": None,
        "rationale": None,
        "owner": None,
        "review_status": None,
        "review_date": None,
    }
    assert controls["AZ-NET-001"]["status"] == "PASS"
    assert controls["AZ-NET-001"]["severity"] is None
