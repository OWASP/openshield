"""Regression tests for DB-backed async scan state.

These tests protect against reintroducing an in-memory scan job store. The API
must persist queued scan state through DatabaseManager so status survives web
process restarts.
"""

from unittest.mock import MagicMock, patch

import pytest

from api.models.finding import DatabaseManager, LostLease


class _Cursor:
    def __init__(self, rows=None, rowcounts=None):
        self.rows = rows or []
        self.rowcounts = rowcounts or []
        self.calls = []
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        if self.rowcounts:
            self.rowcount = self.rowcounts.pop(0)

    def fetchone(self):
        if self.rows:
            return self.rows.pop(0)
        return None

    def fetchall(self):
        rows, self.rows = self.rows, []
        return rows


def test_trigger_scan_persists_pending_scan_to_database(client, auth_headers, monkeypatch):
    """POST /api/scans/trigger should create a pending DB row, not an in-memory job."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://ci:ci@localhost/ci_db")
    scan_id = "11111111-1111-1111-1111-111111111111"
    subscription_id = "00000000-0000-0000-0000-000000000000"
    mock_db = MagicMock()
    mock_db.admit_scan.return_value = ({"scan_id": scan_id, "status": "pending"}, True)

    with patch("api.routes.scans.DatabaseManager", return_value=mock_db) as db_class:
        with patch("api.routes.scans.uuid.uuid4", return_value=scan_id):
            resp = client.post(
                "/api/scans/trigger",
                json={"subscription_id": subscription_id},
                headers=auth_headers,
            )

    assert resp.status_code == 202
    assert resp.get_json() == {
        "scan_id": scan_id,
        "status": "pending",
        "message": "Scan has been queued and will start shortly.",
    }
    db_class.assert_called_once_with("postgresql://ci:ci@localhost/ci_db")
    mock_db.connect.assert_called_once()
    mock_db.admit_scan.assert_called_once()
    assert mock_db.admit_scan.call_args.args[:2] == (scan_id, subscription_id)


def test_trigger_scan_replays_an_existing_scan_for_a_repeated_key(client, auth_headers, monkeypatch):
    """A repeated Idempotency-Key returns the original scan with 200, not a new one."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://ci:ci@localhost/ci_db")
    scan_id = "11111111-1111-1111-1111-111111111111"
    subscription_id = "00000000-0000-0000-0000-000000000000"
    mock_db = MagicMock()
    # created=False is how admission reports "this resolved to an existing scan".
    mock_db.admit_scan.return_value = ({"scan_id": scan_id, "status": "running"}, False)

    with patch("api.routes.scans.DatabaseManager", return_value=mock_db):
        resp = client.post(
            "/api/scans/trigger",
            json={"subscription_id": subscription_id},
            headers={**auth_headers, "Idempotency-Key": "repeat-me"},
        )

    assert resp.status_code == 200
    assert resp.get_json() == {
        "scan_id": scan_id,
        "status": "running",
        "message": "Existing logical scan returned.",
    }
    assert mock_db.admit_scan.call_args.kwargs["idempotency_key"] == "repeat-me"


def test_trigger_scan_sends_no_request_fingerprint(client, auth_headers, monkeypatch):
    """Admission takes the key alone; there is no second request identity.

    A trigger's only semantic input is subscription_id and keys are scoped to
    a subscription, so a fingerprint derived from the request could never
    differ between two requests that shared a key. It was removed rather than
    left as an unreachable 409 path.
    """
    monkeypatch.setenv("DATABASE_URL", "postgresql://ci:ci@localhost/ci_db")
    mock_db = MagicMock()
    mock_db.admit_scan.return_value = ({"scan_id": "x", "status": "pending"}, True)

    with patch("api.routes.scans.DatabaseManager", return_value=mock_db):
        client.post(
            "/api/scans/trigger",
            json={"subscription_id": "00000000-0000-0000-0000-000000000000"},
            headers={**auth_headers, "Idempotency-Key": "k"},
        )

    assert "request_fingerprint" not in mock_db.admit_scan.call_args.kwargs


def test_get_scan_status_reads_from_database(client, auth_headers, monkeypatch):
    """GET /api/scans/<scan_id> should read durable status from PostgreSQL."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://ci:ci@localhost/ci_db")
    scan_id = "22222222-2222-2222-2222-222222222222"
    mock_db = MagicMock()
    mock_db.get_scan.return_value = {
        "scan_id": scan_id,
        "subscription_id": "00000000-0000-0000-0000-000000000000",
        "status": "running",
        "started_at": "2026-07-07T12:00:00Z",
        "completed_at": None,
        "total_findings": 0,
        "score": None,
        "error_message": None,
    }

    with patch("api.routes.scans.DatabaseManager", return_value=mock_db) as db_class:
        resp = client.get(f"/api/scans/{scan_id}", headers=auth_headers)

    assert resp.status_code == 200
    assert resp.get_json()["status"] == "running"
    db_class.assert_called_once_with("postgresql://ci:ci@localhost/ci_db")
    mock_db.connect.assert_called_once()
    mock_db.get_scan.assert_called_once_with(scan_id)


def test_get_scan_status_returns_not_found_for_missing_database_row(client, auth_headers, monkeypatch):
    """Missing persisted scan state should return 404 instead of consulting memory."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://ci:ci@localhost/ci_db")
    scan_id = "33333333-3333-3333-3333-333333333333"
    mock_db = MagicMock()
    mock_db.get_scan.return_value = None

    with patch("api.routes.scans.DatabaseManager", return_value=mock_db):
        resp = client.get(f"/api/scans/{scan_id}", headers=auth_headers)

    assert resp.status_code == 404
    assert resp.get_json() == {"error": "Scan not found"}
    mock_db.get_scan.assert_called_once_with(scan_id)


def test_claim_next_pending_scan_increments_attempt_count():
    """Claiming a pending scan should record a durable execution attempt."""
    db = DatabaseManager.__new__(DatabaseManager)
    scan_id = "44444444-4444-4444-4444-444444444444"
    cursor = _Cursor(rows=[{"scan_id": scan_id, "attempt_count": 1, "fencing_token": 1}])
    conn = MagicMock()
    conn.cursor.return_value = cursor

    with patch.object(db, "_get_conn", return_value=conn):
        scan = db.claim_next_pending_scan("worker-a", 900)

    executed_sql = cursor.calls[0][0]
    assert "attempt_count = COALESCE(attempt_count, 0) + 1" in executed_sql
    assert "lease_owner = %s" in executed_sql
    assert "lease_expires_at = CURRENT_TIMESTAMP" in executed_sql
    assert "fencing_token = COALESCE(fencing_token, 0) + 1" in executed_sql
    assert "error_message = NULL" in executed_sql
    assert scan["scan_id"] == scan_id
    conn.commit.assert_called_once()


def test_empty_claim_commits_before_the_worker_can_sleep():
    """A no-work poll must not leave the long-lived worker transaction open."""
    db = DatabaseManager.__new__(DatabaseManager)
    cursor = _Cursor(rows=[])
    conn = MagicMock()
    conn.cursor.return_value = cursor

    with patch.object(db, "_get_conn", return_value=conn):
        assert db.claim_next_pending_scan("worker-a", 900) is None

    conn.commit.assert_called_once()


def test_heartbeat_requires_current_owner_token_and_unexpired_lease():
    db = DatabaseManager.__new__(DatabaseManager)
    cursor = _Cursor(rows=[])
    conn = MagicMock()
    conn.closed = 0
    conn.info.transaction_status = 0
    conn.cursor.return_value = cursor

    with patch.object(db, "_get_conn", return_value=conn):
        with pytest.raises(LostLease):
            db.heartbeat_scan("scan-1", "worker-a", 3, 900)

    sql = cursor.calls[0][0]
    assert "lease_owner = %s" in sql
    assert "fencing_token = %s" in sql
    assert "lease_expires_at > CURRENT_TIMESTAMP" in sql
    conn.rollback.assert_called_once()


def test_fenced_failure_rejects_a_stale_owner():
    db = DatabaseManager.__new__(DatabaseManager)
    cursor = _Cursor(rows=[])
    conn = MagicMock()
    conn.closed = 0
    conn.info.transaction_status = 0
    conn.cursor.return_value = cursor

    with patch.object(db, "_get_conn", return_value=conn):
        with pytest.raises(LostLease):
            db.update_scan_status(
                "scan-1",
                "failed",
                "failure",
                lease_owner="worker-a",
                fencing_token=3,
            )

    sql = cursor.calls[0][0]
    assert "lease_owner = %s" in sql
    assert "fencing_token = %s" in sql
    assert "lease_expires_at > CURRENT_TIMESTAMP" in sql


def test_recover_stale_scans_transitions_candidates_in_one_locked_statement():
    """Selection and transition must be a single SKIP LOCKED statement.

    Two sequential UPDATEs waited on any row another transaction held, which
    stalled the whole worker loop because recovery runs before claiming.
    """
    db = DatabaseManager.__new__(DatabaseManager)
    cursor = _Cursor(rows=[("pending",), ("failed",)])
    conn = MagicMock()
    conn.cursor.return_value = cursor

    with patch.object(db, "_get_conn", return_value=conn):
        recovered = db.recover_stale_scans(max_attempts=3)

    assert len(cursor.calls) == 1
    sql, params = cursor.calls[0]
    assert "FOR UPDATE SKIP LOCKED" in sql
    assert "lease_expires_at < CURRENT_TIMESTAMP" in sql
    assert "status = 'running'" in sql
    assert "lease_owner = NULL" in sql
    assert params == {"max_attempts": 3}
    # Both transitions are reported from the one statement's RETURNING rows.
    assert recovered == 2
    conn.commit.assert_called_once()


def test_recover_stale_scans_defaults_a_missing_attempt_count_to_zero():
    """Retry and exhaustion must read attempt_count the same way.

    The fail branch previously defaulted NULL to 1 while the retry branch
    defaulted it to 0, retiring rows that predate the column a run early.
    """
    db = DatabaseManager.__new__(DatabaseManager)
    cursor = _Cursor(rows=[("failed",)])
    conn = MagicMock()
    conn.cursor.return_value = cursor

    with patch.object(db, "_get_conn", return_value=conn):
        recovered = db.recover_stale_scans(max_attempts=3)

    sql, _params = cursor.calls[0]
    assert "COALESCE(attempt_count, 0)" in sql
    assert "COALESCE(attempt_count, 1)" not in sql
    assert recovered == 1
