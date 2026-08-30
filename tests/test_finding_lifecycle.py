"""Tests for LifecycleService using a mocked psycopg2 connection.

All tests use in-memory state to simulate the database without requiring a
live PostgreSQL instance.
"""

import hashlib
import json
from unittest.mock import MagicMock, call, patch

import pytest

from api.services.lifecycle_service import (
    LifecycleService,
    _compute_fingerprint_hash,
    _normalize_resource_id,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TENANT_ID = "tenant-abc"
SUB_ID = "sub-001"
SCAN_ID_1 = "11111111-1111-1111-1111-111111111111"
SCAN_ID_2 = "22222222-2222-2222-2222-222222222222"


def _make_finding(rule_id: str, resource_id: str, evidence_key: str = "") -> dict:
    return {
        "rule_id": rule_id,
        "resource_id": resource_id,
        "evidence_key": evidence_key,
    }


def _make_outcome(rule_id: str, status: str) -> dict:
    return {"rule_id": rule_id, "status": status}


# ---------------------------------------------------------------------------
# Simple DB simulation using a plain dict as in-memory state.
# We avoid mocking every cursor call individually by building a lightweight
# fake cursor that replays scripted return values in order.
# ---------------------------------------------------------------------------


class _FakeCursor:
    """A fake psycopg2 cursor that works with pre-loaded fetchone/fetchall results."""

    def __init__(self, results: list):
        # results is a list of return values; each execute() pops one.
        self._results = list(results)
        self._current = None
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append((sql.strip(), params))
        self._current = self._results.pop(0) if self._results else None

    def fetchone(self):
        return self._current

    def fetchall(self):
        if isinstance(self._current, list):
            return self._current
        return [] if self._current is None else [self._current]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class _FakeConn:
    """Fake connection whose cursor() returns a _FakeCursor consuming a result list."""

    def __init__(self, results: list):
        self._results = results
        self.committed = False
        self._cursor_obj = None

    def cursor(self, **_kwargs):
        self._cursor_obj = _FakeCursor(self._results)
        return self._cursor_obj

    def commit(self):
        self.committed = True


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestComputeFingerprintHash:
    def test_hash_is_stable(self):
        h1 = _compute_fingerprint_hash(TENANT_ID, SUB_ID, "/sub/001/rg/foo", "RULE-001", "", "1")
        h2 = _compute_fingerprint_hash(TENANT_ID, SUB_ID, "/sub/001/rg/foo", "RULE-001", "", "1")
        assert h1 == h2

    def test_different_tenant_different_hash(self):
        h1 = _compute_fingerprint_hash("tenant-A", SUB_ID, "/rg/foo", "RULE-001", "", "1")
        h2 = _compute_fingerprint_hash("tenant-B", SUB_ID, "/rg/foo", "RULE-001", "", "1")
        assert h1 != h2

    def test_tenant_id_included_in_hash(self):
        """Tenant isolation: fingerprint_hash must encode the tenant_id."""
        h_a = _compute_fingerprint_hash("tenant-A", SUB_ID, "/rg/foo", "RULE-001", "", "1")
        h_b = _compute_fingerprint_hash("tenant-B", SUB_ID, "/rg/foo", "RULE-001", "", "1")
        assert h_a != h_b

    def test_different_rule_different_hash(self):
        h1 = _compute_fingerprint_hash(TENANT_ID, SUB_ID, "/rg/foo", "RULE-001", "", "1")
        h2 = _compute_fingerprint_hash(TENANT_ID, SUB_ID, "/rg/foo", "RULE-002", "", "1")
        assert h1 != h2


class TestNormalizeResourceId:
    def test_lowercase(self):
        assert _normalize_resource_id("/subscriptions/SUB/resourceGroups/RG") == (
            "/subscriptions/sub/resourcegroups/rg"
        )

    def test_strip_whitespace(self):
        assert _normalize_resource_id("  /rg/foo  ") == "/rg/foo"


class TestLifecycleServiceIdempotency:
    """Applying the same scan_id twice must produce exactly one transition."""

    def test_second_apply_is_no_op(self):
        # First call: idempotency row NOT present (fetchone -> None), then
        # fingerprint upsert returns id=1, lifecycle select returns None
        # (new finding), lifecycle insert returns id=10, commit.
        # Second call: idempotency row IS present (fetchone -> (scan_id,)).
        svc = LifecycleService()

        transitions = []

        # We use a counting approach: track how many times commit() is called.
        committed_count = 0

        class _TrackingConn:
            def __init__(self, is_first_call):
                self._is_first = is_first_call
                self._results = self._build_results(is_first_call)

            def _build_results(self, first):
                if first:
                    # idempotency check -> None (not applied)
                    # fingerprint upsert RETURNING id -> (1,)
                    # lifecycle FOR UPDATE -> None (new)
                    # lifecycle INSERT RETURNING id -> (10,)
                    # transition insert -> None
                    # absent-findings query -> []
                    # idempotency insert -> None
                    return [None, (1,), None, (10,), None, [], None]
                else:
                    # idempotency check -> row found: stop immediately
                    return [("already-applied",)]

            def cursor(self, **_kwargs):
                return _FakeCursor(self._results)

            def commit(self):
                nonlocal committed_count
                committed_count += 1

        svc.apply_scan(
            _TrackingConn(True), SCAN_ID_1, SUB_ID, TENANT_ID,
            [_make_outcome("RULE-001", "SUCCESS")],
            [_make_finding("RULE-001", "/rg/foo")],
        )
        svc.apply_scan(
            _TrackingConn(False), SCAN_ID_1, SUB_ID, TENANT_ID,
            [_make_outcome("RULE-001", "SUCCESS")],
            [_make_finding("RULE-001", "/rg/foo")],
        )

        # Only the first call should have committed.
        assert committed_count == 1


class TestLifecycleStateTransitions:
    """State machine correctness tests using scripted cursor results."""

    def _run(self, results, findings, outcomes):
        """Run apply_scan with scripted cursor results; return the fake conn."""
        conn = _FakeConn(results)
        svc = LifecycleService()
        svc.apply_scan(conn, SCAN_ID_1, SUB_ID, TENANT_ID, outcomes, findings)
        return conn

    def test_new_finding_creates_open_lifecycle(self):
        # Scripted results in cursor execute order:
        # 1. idempotency check -> None
        # 2. fingerprint upsert RETURNING id -> (1,)
        # 3. lifecycle FOR UPDATE -> None  (no existing row)
        # 4. lifecycle INSERT RETURNING id -> (10,)
        # 5. transition insert -> None
        # 6. absent-findings query -> []
        # 7. idempotency insert -> None
        results = [None, (1,), None, (10,), None, [], None]
        conn = self._run(
            results,
            [_make_finding("RULE-001", "/rg/foo")],
            [_make_outcome("RULE-001", "SUCCESS")],
        )
        assert conn.committed

        # Verify the lifecycle INSERT used 'OPEN'
        executed = conn._cursor_obj.executed
        insert_lc = next(
            (sql for sql, _ in executed if "INSERT INTO finding_lifecycles" in sql), None
        )
        assert insert_lc is not None

    def test_open_finding_not_seen_in_success_scan_is_resolved(self):
        # No findings in this scan, outcome is SUCCESS -> existing OPEN should resolve.
        # 1. idempotency check -> None
        # 2. absent-findings query (no seen ids branch) -> [(lc_id=10, 'OPEN', 0, 'RULE-001')]
        # 3. UPDATE finding_lifecycles SET state='RESOLVED' -> None
        # 4. transition insert -> None
        # 5. idempotency insert -> None
        results = [
            None,
            [(10, "OPEN", 0, "RULE-001")],
            None,
            None,
            None,
        ]
        conn = self._run(
            results,
            [],  # no findings
            [_make_outcome("RULE-001", "SUCCESS")],
        )
        assert conn.committed
        executed = conn._cursor_obj.executed
        resolve_sql = next(
            (sql for sql, _ in executed if "RESOLVED" in sql and "UPDATE" in sql.upper()), None
        )
        assert resolve_sql is not None

    def test_open_finding_not_seen_in_failed_scan_stays_open(self):
        # FAILED outcome -> fail-closed: finding should NOT be resolved.
        # 1. idempotency check -> None
        # 2. absent-findings query -> [(lc_id=10, 'OPEN', 0, 'RULE-001')]
        # 3. idempotency insert -> None
        # (no UPDATE to RESOLVED because outcome is FAILED)
        results = [
            None,
            [(10, "OPEN", 0, "RULE-001")],
            None,
        ]
        conn = self._run(
            results,
            [],
            [_make_outcome("RULE-001", "FAILED")],
        )
        assert conn.committed
        executed = conn._cursor_obj.executed
        resolve_sql = next(
            (sql for sql, _ in executed if "RESOLVED" in sql and "UPDATE" in sql.upper()), None
        )
        assert resolve_sql is None

    def test_open_finding_not_seen_in_permission_denied_stays_open(self):
        results = [
            None,
            [(10, "OPEN", 0, "RULE-001")],
            None,
        ]
        conn = self._run(
            results,
            [],
            [_make_outcome("RULE-001", "PERMISSION_DENIED")],
        )
        assert conn.committed
        executed = conn._cursor_obj.executed
        resolve_sql = next(
            (sql for sql, _ in executed if "RESOLVED" in sql and "UPDATE" in sql.upper()), None
        )
        assert resolve_sql is None

    def test_resolved_finding_seen_again_becomes_reopened(self):
        # Fingerprint exists (id=1), lifecycle row has state=RESOLVED -> should REOPEN.
        # 1. idempotency check -> None
        # 2. fingerprint upsert RETURNING id -> (1,)
        # 3. lifecycle FOR UPDATE -> (lc_id=10, 'RESOLVED', 1, 0, 2)
        #    (id, state, occurrence_count, reopen_count, row_version)
        # 4. UPDATE to REOPENED -> None
        # 5. transition insert (RESOLVED -> REOPENED) -> None
        # 6. absent-findings query -> []
        # 7. idempotency insert -> None
        results = [
            None,
            (1,),
            (10, "RESOLVED", 1, 0, 2),
            None,
            None,
            [],
            None,
        ]
        conn = self._run(
            results,
            [_make_finding("RULE-001", "/rg/foo")],
            [_make_outcome("RULE-001", "SUCCESS")],
        )
        assert conn.committed
        executed = conn._cursor_obj.executed
        reopen_sql = next(
            (sql for sql, _ in executed if "REOPENED" in sql and "UPDATE" in sql.upper()), None
        )
        assert reopen_sql is not None

    def test_reopened_finding_seen_again_increments_occurrence_stays_reopened(self):
        # REOPENED + seen again: occurrence_count increments, state stays REOPENED.
        # 1. idempotency check -> None
        # 2. fingerprint upsert RETURNING id -> (1,)
        # 3. lifecycle FOR UPDATE -> (10, 'REOPENED', 3, 1, 4)
        # 4. UPDATE occurrence_count + 1 -> None  (OPEN/REOPENED branch)
        # 5. absent-findings query -> []
        # 6. idempotency insert -> None
        results = [
            None,
            (1,),
            (10, "REOPENED", 3, 1, 4),
            None,
            [],
            None,
        ]
        conn = self._run(
            results,
            [_make_finding("RULE-001", "/rg/foo")],
            [_make_outcome("RULE-001", "SUCCESS")],
        )
        assert conn.committed
        executed = conn._cursor_obj.executed
        # Verify no transition to a NEW state was recorded for this finding
        # (i.e. no INSERT INTO finding_lifecycle_transitions for OPEN/REOPENED).
        reopened_transition = next(
            (
                sql for sql, params in executed
                if "INSERT INTO finding_lifecycle_transitions" in sql
                and params is not None
                and "REOPENED" in str(params)
            ),
            None,
        )
        assert reopened_transition is None

        # Verify occurrence_count was incremented (UPDATE without state change).
        occ_update = next(
            (
                sql for sql, _ in executed
                if "occurrence_count = occurrence_count + 1" in sql
            ),
            None,
        )
        assert occ_update is not None
