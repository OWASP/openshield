"""Tests for DatabaseManager reliability fixes (REL-001, REL-002, REL-003)."""

from unittest.mock import MagicMock, patch

import api.models.finding as finding_module


def _db(dsn="postgresql://mock/mock"):
    """Return a DatabaseManager with a mock DSN (no real connection used)."""
    db = finding_module.DatabaseManager.__new__(finding_module.DatabaseManager)
    db.dsn = dsn
    db.conn = None
    return db


def _mock_cursor(rows=None, rowcount=0):
    cur = MagicMock()
    cur.__enter__ = lambda s: s
    cur.__exit__ = MagicMock(return_value=False)
    cur.fetchall.return_value = rows or []
    cur.fetchone.return_value = rows[0] if rows else None
    cur.rowcount = rowcount
    return cur


# ── REL-001: get_score must issue valid SQL (single GROUP BY) ──────────────


def test_get_score_sql_has_single_group_by():
    db = _db()
    conn = MagicMock()
    conn.cursor.return_value = _mock_cursor([])
    with patch.object(db, "_get_conn", return_value=conn):
        db.get_score()
    executed_sql = conn.cursor.return_value.execute.call_args[0][0]
    assert executed_sql.count("GROUP BY") == 1


def test_get_score_deducts_points_for_findings():
    db = _db()
    conn = MagicMock()
    conn.cursor.return_value = _mock_cursor([("HIGH", 2), ("MEDIUM", 1)])
    with patch.object(db, "_get_conn", return_value=conn):
        score = db.get_score()
    # 100 - (10 * 2 + 5 * 1) = 75
    assert score == 75


# REL-002 (recover_stale_scans's interval handling) is now covered by
# tests/test_async_scan_persistence.py's attempt-count-based tests, which
# supersede this file's original single-query, single-param version of the
# function.


# ── REL-003: connections are borrowed from / returned to a shared pool ─────


def test_connect_acquires_connection_from_shared_pool():
    dsn = "postgresql://pool-test/db"
    fake_pool = MagicMock()
    fake_conn = MagicMock()
    fake_conn.closed = 0
    fake_pool.getconn.return_value = fake_conn

    with patch.object(finding_module, "_get_pool", return_value=fake_pool) as mock_get_pool:
        db = finding_module.DatabaseManager(dsn)
        db.connect()

    mock_get_pool.assert_called_once_with(dsn)
    fake_pool.getconn.assert_called_once()
    assert db.conn is fake_conn


def test_reconnect_rolls_back_and_returns_previous_connection_once():
    dsn = "postgresql://pool-test/db"
    fake_pool = MagicMock()
    old_conn = MagicMock()
    old_conn.closed = 0
    old_conn.info.transaction_status = 0
    new_conn = MagicMock()
    new_conn.closed = 0
    fake_pool.getconn.return_value = new_conn
    db = _db(dsn)
    db.conn = old_conn

    with patch.object(finding_module, "_get_pool", return_value=fake_pool):
        db.connect()

    old_conn.rollback.assert_called_once()
    fake_pool.putconn.assert_called_once_with(old_conn, close=False)
    fake_pool.getconn.assert_called_once()
    assert db.conn is new_conn


def test_close_returns_healthy_connection_to_pool():
    dsn = "postgresql://pool-test/db"
    fake_pool = MagicMock()
    fake_conn = MagicMock()
    fake_conn.closed = 0
    db = _db(dsn)
    db.conn = fake_conn

    with patch.object(finding_module, "_get_pool", return_value=fake_pool) as mock_get_pool:
        db.close()

    mock_get_pool.assert_called_once_with(dsn)
    fake_pool.putconn.assert_called_once_with(fake_conn, close=False)
    assert db.conn is None


def test_close_discards_broken_connection_instead_of_pooling_it():
    dsn = "postgresql://pool-test/db"
    fake_pool = MagicMock()
    fake_conn = MagicMock()
    fake_conn.closed = 1  # already closed / broken
    db = _db(dsn)
    db.conn = fake_conn

    with patch.object(finding_module, "_get_pool", return_value=fake_pool):
        db.close()

    fake_pool.putconn.assert_called_once_with(fake_conn, close=True)


def test_get_pool_reuses_same_instance_per_dsn(monkeypatch):
    monkeypatch.setattr(finding_module, "_POOLS", {})
    created_dsns = []

    class FakePool:
        def __init__(self, minconn, maxconn, dsn):
            created_dsns.append(dsn)

    monkeypatch.setattr(finding_module.psycopg2.pool, "ThreadedConnectionPool", FakePool)

    pool_a1 = finding_module._get_pool("dsn-a")
    pool_a2 = finding_module._get_pool("dsn-a")
    pool_b = finding_module._get_pool("dsn-b")

    assert pool_a1 is pool_a2
    assert pool_a1 is not pool_b
    assert created_dsns == ["dsn-a", "dsn-b"]
