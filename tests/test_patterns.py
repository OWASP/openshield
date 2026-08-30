"""Tests for PatternService and GET /api/v1/patterns routes.

Pattern detection tests use a mocked DB; route tests use the Flask test client
with mocked database queries.
"""

import secrets
import time
from collections import deque
from unittest.mock import MagicMock, patch

import jwt
import pytest

TENANT_ID = "tenant-abc"
SUB_ID = "sub-001"
SCAN_ID = "33333333-3333-3333-3333-333333333333"

_TEST_JWT_SECRET = secrets.token_urlsafe(32)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_token(sub_id: str | None = None) -> str:
    payload = {
        "sub": "test-user",
        "role": "admin",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    if sub_id:
        payload["subscription_id"] = sub_id
    return jwt.encode(payload, _TEST_JWT_SECRET, algorithm="HS256")


def _auth_headers(sub_id: str | None = None) -> dict:
    return {
        "Authorization": f"Bearer {_make_token(sub_id)}",
        "Content-Type": "application/json",
    }


# ---------------------------------------------------------------------------
# Fake cursor / connection for service tests
# ---------------------------------------------------------------------------


class _FakeCursor:
    """Fake cursor backed by a shared deque so all cursors on one connection share state."""

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

    def __init__(self, fetchall_pages: list):
        self._deque: deque = deque(fetchall_pages)
        self.committed = False
        self._cursors: list = []
        self._cursor_obj = None

    def cursor(self, **_kwargs):
        self._cursor_obj = _FakeCursor(self._deque)
        self._cursors.append(self._cursor_obj)
        return self._cursor_obj

    def commit(self):
        self.committed = True

    def rollback(self):
        pass

    def all_executed(self) -> list:
        result = []
        for c in self._cursors:
            result.extend(c.executed)
        return result


# ---------------------------------------------------------------------------
# PatternService unit tests
# ---------------------------------------------------------------------------


class TestPatternServiceDetection:
    def _run(self, pages, extra_pages=None):
        """Run detect_and_publish with scripted DB results."""
        from api.services.pattern_service import PatternService

        all_pages = list(pages)
        if extra_pages:
            all_pages.extend(extra_pages)
        conn = _FakeConn(all_pages)
        svc = PatternService()
        count = svc.detect_and_publish(conn, SCAN_ID, SUB_ID, TENANT_ID)
        return count, conn

    def test_persistent_finding_detected_when_occurrence_ge_3(self):
        # persistent_finding query returns 1 row -> 1 pattern upserted.
        # cross_resource query returns [] -> 0.
        # reopened query returns [] -> 0.
        count, conn = self._run(
            [
                [{"lifecycle_id": 10}],  # persistent_finding
                [],  # cross_resource_recurrence
                [],  # reopened_finding
            ]
        )
        assert count == 1

    def test_persistent_finding_not_detected_when_occurrence_lt_3(self):
        # All queries return empty.
        count, conn = self._run([[], [], []])
        assert count == 0

    def test_cross_resource_recurrence_detected_when_2_open_lifecycles(self):
        # cross_resource query returns 1 group with 2 lifecycle_ids -> 2 patterns.
        count, conn = self._run(
            [
                [],  # persistent_finding
                [{"rule_id": "RULE-001", "lifecycle_ids": [10, 11], "lc_count": 2}],
                [],  # reopened_finding
            ]
        )
        assert count == 2

    def test_reopened_finding_detected_when_reopen_count_ge_1(self):
        count, conn = self._run(
            [
                [],  # persistent_finding
                [],  # cross_resource_recurrence
                [{"lifecycle_id": 20}],  # reopened_finding
            ]
        )
        assert count == 1

    def test_pattern_response_includes_threshold_and_algorithm_version(self):
        """The upsert call must include threshold and algorithm_version."""
        from api.services.pattern_service import PatternService, _ALGORITHM_VERSION, _PERSISTENT_THRESHOLD

        conn = _FakeConn(
            [
                [{"lifecycle_id": 10}],  # persistent_finding
                [],  # cross_resource_recurrence
                [],  # reopened_finding
            ]
        )
        svc = PatternService()
        svc.detect_and_publish(conn, SCAN_ID, SUB_ID, TENANT_ID)

        # Find the INSERT INTO patterns call and verify the params.
        executed = conn._cursor_obj.executed
        insert_sql, params = next(((sql, p) for sql, p in executed if "INSERT INTO patterns" in sql), (None, None))
        assert insert_sql is not None
        # params order: pattern_type, lifecycle_id, tenant_id, subscription_id,
        #               scan_id, finding_ids, threshold, algorithm_version
        assert params[6] == _PERSISTENT_THRESHOLD
        assert params[7] == _ALGORITHM_VERSION


# ---------------------------------------------------------------------------
# Flask route tests for GET /api/v1/patterns
# ---------------------------------------------------------------------------


@pytest.fixture
def app_client(monkeypatch):
    """Flask test client with JWT and mocked DB."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://fake/fake")
    monkeypatch.setenv("JWT_SECRET", _TEST_JWT_SECRET)

    from api.app import create_app

    application = create_app()
    application.config["TESTING"] = True
    application.config["JWT_SECRET"] = _TEST_JWT_SECRET
    return application.test_client()


def _mock_db_rows(rows: list, total: int):
    """Build a mock DatabaseManager whose conn returns scripted rows."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
    mock_cursor.__exit__ = MagicMock(return_value=False)

    # First fetchall -> rows; second fetchone -> {"count": total}
    mock_cursor.fetchall.return_value = rows
    mock_cursor.fetchone.return_value = {"count": total}

    mock_conn.cursor.return_value = mock_cursor

    mock_db = MagicMock()
    mock_db._get_conn.return_value = mock_conn
    return mock_db


def _sample_pattern_row(sub_id: str = SUB_ID) -> dict:
    from datetime import datetime, timezone

    return {
        "id": 1,
        "pattern_type": "persistent_finding",
        "lifecycle_id": 10,
        "tenant_id": TENANT_ID,
        "subscription_id": sub_id,
        "scan_id": "33333333-3333-3333-3333-333333333333",
        "finding_ids": [],
        "threshold": 3,
        "algorithm_version": "1",
        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "updated_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
    }


class TestPatternsRouteList:
    def test_list_returns_patterns_and_total(self, app_client, monkeypatch):
        row = _sample_pattern_row()
        mock_db = _mock_db_rows([row], 1)

        with patch("api.routes.patterns._get_db", return_value=mock_db):
            resp = app_client.get(
                "/api/v1/patterns",
                headers=_auth_headers(sub_id=SUB_ID),
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert "patterns" in data
        assert "total" in data
        assert data["total"] == 1
        assert len(data["patterns"]) == 1

    def test_list_invalid_limit_returns_400(self, app_client):
        resp = app_client.get(
            "/api/v1/patterns?limit=999",
            headers=_auth_headers(sub_id=SUB_ID),
        )
        assert resp.status_code == 400

    def test_list_invalid_pattern_type_returns_400(self, app_client):
        resp = app_client.get(
            "/api/v1/patterns?pattern_type=not_a_real_type",
            headers=_auth_headers(sub_id=SUB_ID),
        )
        assert resp.status_code == 400

    def test_list_unknown_query_param_returns_400(self, app_client):
        resp = app_client.get(
            "/api/v1/patterns?foo=bar",
            headers=_auth_headers(sub_id=SUB_ID),
        )
        assert resp.status_code == 400

    def test_list_without_subscription_returns_400(self, app_client):
        # JWT with no subscription_id and no query param must be rejected.
        resp = app_client.get(
            "/api/v1/patterns",
            headers=_auth_headers(),
        )
        assert resp.status_code == 400

    def test_list_cross_subscription_query_param_rejected(self, app_client):
        # JWT scoped to sub-A must reject a query param asking for sub-B.
        resp = app_client.get(
            "/api/v1/patterns?subscription_id=sub-B",
            headers=_auth_headers(sub_id="sub-A"),
        )
        assert resp.status_code == 400

    def test_list_returns_only_authorized_subscription(self, app_client):
        """subscription_id from JWT must be passed as a SQL parameter."""
        row_authorized = _sample_pattern_row(sub_id="sub-authorized")
        mock_db = _mock_db_rows([row_authorized], 1)

        with patch("api.routes.patterns._get_db", return_value=mock_db):
            resp = app_client.get(
                "/api/v1/patterns",
                headers=_auth_headers(sub_id="sub-authorized"),
            )

        assert resp.status_code == 200
        # Verify subscription_id was enforced in the SQL WHERE clause parameters.
        mock_cursor = mock_db._get_conn.return_value.cursor.return_value
        first_call = mock_cursor.execute.call_args_list[0]
        _, params = first_call[0]
        assert "sub-authorized" in params

    def test_list_requires_auth(self, app_client):
        resp = app_client.get("/api/v1/patterns")
        assert resp.status_code == 401


class TestPatternsRouteGet:
    def _mock_get_db(self, row):
        mock_db = MagicMock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_cursor.fetchone.return_value = row
        mock_conn.cursor.return_value = mock_cursor
        mock_db._get_conn.return_value = mock_conn
        return mock_db

    def test_get_existing_pattern(self, app_client):
        row = _sample_pattern_row()
        mock_db = self._mock_get_db(row)

        with patch("api.routes.patterns._get_db", return_value=mock_db):
            resp = app_client.get(
                "/api/v1/patterns/1",
                headers=_auth_headers(sub_id=SUB_ID),
            )

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["id"] == 1
        assert data["pattern_type"] == "persistent_finding"
        assert data["threshold"] == 3
        assert data["algorithm_version"] == "1"

    def test_get_nonexistent_pattern_returns_404(self, app_client):
        # DB returns None when id + subscription_id don't match any row.
        mock_db = self._mock_get_db(None)

        with patch("api.routes.patterns._get_db", return_value=mock_db):
            resp = app_client.get(
                "/api/v1/patterns/99999",
                headers=_auth_headers(sub_id=SUB_ID),
            )

        assert resp.status_code == 404

    def test_get_cross_subscription_returns_404(self, app_client):
        # Pattern exists for sub-001 but caller is scoped to sub-other.
        # The SQL adds subscription_id = %s to the WHERE clause so the DB
        # returns None, and the caller sees 404 (not 403, to avoid leaking
        # that the pattern ID exists in another subscription).
        mock_db = self._mock_get_db(None)

        with patch("api.routes.patterns._get_db", return_value=mock_db):
            resp = app_client.get(
                "/api/v1/patterns/1",
                headers=_auth_headers(sub_id="sub-other"),
            )

        assert resp.status_code == 404
        # Verify subscription_id was enforced as a SQL parameter (not just checked
        # in Python), so removing the WHERE clause would break this test.
        mock_cursor = mock_db._get_conn.return_value.cursor.return_value
        call_args = mock_cursor.execute.call_args
        _, params = call_args[0]
        assert "sub-other" in params

    def test_get_requires_auth(self, app_client):
        resp = app_client.get("/api/v1/patterns/1")
        assert resp.status_code == 401
