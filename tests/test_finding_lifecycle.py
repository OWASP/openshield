"""Tests for LifecycleService using a mocked psycopg2 connection.

All tests use in-memory state to simulate the database without requiring a
live PostgreSQL instance.
"""

from collections import deque

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
# Fake cursor / connection.
#
# The cursor consumes from a shared deque so multiple cursor() calls on the
# same connection share one result stream. This mirrors how psycopg2 works
# (multiple cursors on one connection see the same transaction state) and
# avoids the "second cursor re-reads from the start" bug noted in code review.
# ---------------------------------------------------------------------------


class _FakeCursor:
    """Fake psycopg2 cursor backed by a shared result deque."""

    def __init__(self, results_deque: deque):
        self._results = results_deque
        self.executed: list = []
        self._current = None

    def execute(self, sql, params=None):
        self.executed.append((sql.strip(), params))
        self._current = self._results.popleft() if self._results else None

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
    """Fake connection whose cursor() calls share one result deque."""

    def __init__(self, results: list):
        self._deque: deque = deque(results)
        self.committed = False
        self._cursor_obj: _FakeCursor | None = None

    def cursor(self, **_kwargs):
        # Return a new cursor object but backed by the same shared deque.
        self._cursor_obj = _FakeCursor(self._deque)
        return self._cursor_obj

    def commit(self):
        self.committed = True

    def rollback(self):
        pass

    def all_executed(self) -> list:
        return self._cursor_obj.executed if self._cursor_obj else []


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
    """Applying the same scan_id twice must commit exactly once."""

    def test_second_apply_is_no_op(self):
        committed_count = 0

        class _TrackingConn:
            def __init__(self, already_applied: bool):
                if already_applied:
                    # idempotency check returns a row -> return immediately
                    results = [("already-applied",)]
                else:
                    # idempotency check None, outcome insert None,
                    # fingerprint upsert -> (1,), lifecycle lock -> None (new),
                    # lifecycle insert -> (10,), transition insert None,
                    # absent-findings query -> [], idempotency insert None
                    results = [None, None, (1,), None, (10,), None, [], None]
                self._deque: deque = deque(results)
                self._cursor_obj = None

            def cursor(self, **_kwargs):
                self._cursor_obj = _FakeCursor(self._deque)
                return self._cursor_obj

            def commit(self):
                nonlocal committed_count
                committed_count += 1

            def rollback(self):
                pass

        svc = LifecycleService()
        svc.apply_scan(
            _TrackingConn(False),
            SCAN_ID_1,
            SUB_ID,
            TENANT_ID,
            [_make_outcome("RULE-001", "SUCCESS")],
            [_make_finding("RULE-001", "/rg/foo")],
        )
        svc.apply_scan(
            _TrackingConn(True),
            SCAN_ID_1,
            SUB_ID,
            TENANT_ID,
            [_make_outcome("RULE-001", "SUCCESS")],
            [_make_finding("RULE-001", "/rg/foo")],
        )

        # Only the first call should have committed.
        assert committed_count == 1


class TestLifecycleStateTransitions:
    """State machine correctness tests using scripted cursor results."""

    def _run(self, results, findings, outcomes):
        conn = _FakeConn(results)
        svc = LifecycleService()
        svc.apply_scan(conn, SCAN_ID_1, SUB_ID, TENANT_ID, outcomes, findings)
        return conn

    def _all_sql(self, conn: _FakeConn) -> list[str]:
        return [sql for sql, _ in conn.all_executed()]

    def test_new_finding_creates_open_lifecycle(self):
        # Sequence (one shared deque, all execute() calls in order):
        # 1. idempotency check -> None
        # 2. scan_rule_outcomes insert (for RULE-001 outcome) -> None
        # 3. fingerprint upsert RETURNING id -> (1,)
        # 4. lifecycle FOR UPDATE -> None  (new)
        # 5. lifecycle INSERT RETURNING id -> (10,)
        # 6. transition insert -> None
        # 7. absent-findings query (no resolving ids after seen_fingerprint_ids) -> []
        # 8. idempotency insert -> None
        results = [None, None, (1,), None, (10,), None, [], None]
        conn = self._run(
            results,
            [_make_finding("RULE-001", "/rg/foo")],
            [_make_outcome("RULE-001", "SUCCESS")],
        )
        assert conn.committed
        sqls = self._all_sql(conn)
        assert any("INSERT INTO finding_lifecycles" in s for s in sqls)
        # Transition to OPEN must be recorded.
        assert any("finding_lifecycle_transitions" in s and "'OPEN'" in s for s in sqls)

    def test_scan_rule_outcomes_written(self):
        """scan_rule_outcomes must be populated on every apply_scan call."""
        results = [None, None, (1,), None, (10,), None, [], None]
        conn = self._run(
            results,
            [_make_finding("RULE-001", "/rg/foo")],
            [_make_outcome("RULE-001", "SUCCESS")],
        )
        sqls = self._all_sql(conn)
        assert any("INSERT INTO scan_rule_outcomes" in s for s in sqls)

    def test_open_finding_not_seen_in_success_scan_is_resolved(self):
        # No findings; SUCCESS outcome -> existing OPEN resolved.
        # 1. idempotency check -> None
        # 2. scan_rule_outcomes insert -> None
        # 3. absent-findings query (empty seen_ids branch) -> [(10,'OPEN',0,'RULE-001')]
        # 4. UPDATE to RESOLVED -> None
        # 5. transition insert (OPEN -> RESOLVED) -> None
        # 6. idempotency insert -> None
        results = [
            None,
            None,
            [(10, "OPEN", 0, "RULE-001")],
            None,
            None,
            None,
        ]
        conn = self._run(results, [], [_make_outcome("RULE-001", "SUCCESS")])
        assert conn.committed
        sqls = self._all_sql(conn)
        assert any("RESOLVED" in s and "UPDATE" in s.upper() for s in sqls)

    def test_open_finding_not_seen_in_failed_scan_stays_open(self):
        # FAILED outcome -> fail-closed: no resolution.
        # 1. idempotency check -> None
        # 2. scan_rule_outcomes insert -> None
        # (FAILED is not in resolving_rule_ids; no absent-findings query is issued)
        # 3. idempotency insert -> None
        results = [None, None, None]
        conn = self._run(results, [], [_make_outcome("RULE-001", "FAILED")])
        assert conn.committed
        sqls = self._all_sql(conn)
        assert not any("RESOLVED" in s and "UPDATE" in s.upper() for s in sqls)

    def test_open_finding_not_seen_in_permission_denied_scan_stays_open(self):
        results = [None, None, None]
        conn = self._run(results, [], [_make_outcome("RULE-001", "PERMISSION_DENIED")])
        assert conn.committed
        sqls = self._all_sql(conn)
        assert not any("RESOLVED" in s and "UPDATE" in s.upper() for s in sqls)

    def test_resolved_finding_seen_again_becomes_reopened(self):
        # Fingerprint exists (id=1), lifecycle row has state=RESOLVED -> REOPEN.
        # 1. idempotency check -> None
        # 2. scan_rule_outcomes insert -> None
        # 3. fingerprint upsert RETURNING id -> (1,)
        # 4. lifecycle FOR UPDATE -> (10,'RESOLVED',1,0,2)
        # 5. UPDATE to REOPENED (resets consecutive_success_count=0) -> None
        # 6. transition insert -> None
        # 7. absent-findings query -> []
        # 8. idempotency insert -> None
        results = [None, None, (1,), (10, "RESOLVED", 1, 0, 2), None, None, [], None]
        conn = self._run(
            results,
            [_make_finding("RULE-001", "/rg/foo")],
            [_make_outcome("RULE-001", "SUCCESS")],
        )
        assert conn.committed
        sqls = self._all_sql(conn)
        assert any("REOPENED" in s and "UPDATE" in s.upper() for s in sqls)
        # consecutive_success_count must be reset to 0 on reopen.
        assert any("consecutive_success_count = 0" in s for s in sqls)

    def test_rule_a_success_does_not_resolve_rule_b_finding(self):
        """Rule-A SUCCESS must not resolve a finding belonging to Rule-B.

        This is the most critical correctness invariant: a clean outcome for one
        rule can only affect findings that were produced by that same rule.
        """
        # Scan has no findings (empty list), two outcomes:
        #   RULE-001 SUCCESS  -> in resolving_rule_ids
        #   RULE-002 FAILED   -> NOT in resolving_rule_ids
        #
        # Sequence (empty seen_ids branch):
        # 1. idempotency check -> None
        # 2. scan_rule_outcomes insert RULE-001 -> None
        # 3. scan_rule_outcomes insert RULE-002 -> None
        # 4. absent-findings query (ff.rule_id = ANY(['RULE-001'])) ->
        #    returns only RULE-001's lifecycle row; RULE-002 is excluded by SQL
        # 5. UPDATE RESOLVED for RULE-001 row -> None
        # 6. transition insert -> None
        # 7. idempotency insert -> None
        results = [
            None,  # idempotency check
            None,  # scan_rule_outcomes RULE-001
            None,  # scan_rule_outcomes RULE-002
            [(10, "OPEN", 0, "RULE-001")],  # absent-findings query
            None,  # UPDATE RESOLVED
            None,  # transition insert
            None,  # idempotency insert
        ]
        conn = self._run(
            results,
            [],
            [_make_outcome("RULE-001", "SUCCESS"), _make_outcome("RULE-002", "FAILED")],
        )
        assert conn.committed
        # Verify resolving_rule_ids in the SQL params contains only RULE-001.
        absent_query = next(
            (item for item in conn.all_executed() if "ff.rule_id = ANY" in item[0]),
            None,
        )
        assert absent_query is not None, "absent-findings query was not issued"
        _, params = absent_query
        resolving_ids = params[-1]  # last param is resolving_rule_ids list
        assert "RULE-001" in resolving_ids
        assert "RULE-002" not in resolving_ids

    def test_reopened_finding_seen_again_increments_occurrence_stays_reopened(self):
        # REOPENED + seen in scan: occurrence_count increments, no new state transition.
        # 1. idempotency -> None
        # 2. scan_rule_outcomes insert -> None
        # 3. fingerprint upsert -> (1,)
        # 4. lifecycle FOR UPDATE -> (10,'REOPENED',3,1,4)
        # 5. UPDATE occurrence_count + 1 -> None
        # 6. absent-findings query -> []
        # 7. idempotency insert -> None
        results = [None, None, (1,), (10, "REOPENED", 3, 1, 4), None, [], None]
        conn = self._run(
            results,
            [_make_finding("RULE-001", "/rg/foo")],
            [_make_outcome("RULE-001", "SUCCESS")],
        )
        assert conn.committed
        sqls = self._all_sql(conn)

        # No transition record should be emitted for REOPENED->REOPENED.
        transition_to_reopened = [s for s in sqls if "finding_lifecycle_transitions" in s and "REOPENED" in s]
        assert not transition_to_reopened

        # occurrence_count should increment.
        assert any("occurrence_count = occurrence_count + 1" in s for s in sqls)
