"""Tests for CI scan persistence: CIDatabase and CIScanEngine.run_and_persist().

These tests never touch a real database. All psycopg2 / pool interactions
are patched at the ``api.models.ci_scan`` import boundary, matching the
pattern used in the existing CI rule tests (tests/test_rules_ci_workflow.py).
"""

import json
import uuid
from typing import Any, Dict, List
from unittest.mock import MagicMock, call, patch

import pytest

from api.models.ci_scan import CIDatabase
from scanner.ci_engine import CIScanEngine
from scanner.evaluation import EvaluationStatus, RuleEvaluation

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

OWNER = "test-org"
REPO = "test-repo"
SCAN_ID = str(uuid.uuid4())
DSN = "postgresql://localhost/test"


def _make_evaluation(
    rule_id: str = "AZ-CI-001",
    resource_id: str = f"github/{OWNER}/{REPO}/workflows/.github/workflows/ci.yml",
    status: str = EvaluationStatus.PASS,
    reason_code: str | None = None,
    reason: str | None = None,
    evidence: Dict[str, Any] | None = None,
) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        resource_id=resource_id,
        resource_type="GitHub/WorkflowFile",
        status=status,
        reason_code=reason_code,
        reason=reason,
        evidence=evidence or {},
    )


def _fail_evaluation(rule_id: str = "AZ-CI-001") -> RuleEvaluation:
    return _make_evaluation(
        rule_id=rule_id,
        status=EvaluationStatus.FAIL,
        reason_code="POLICY_VIOLATION",
        reason="Pinned actions required",
    )


def _unknown_evaluation(rule_id: str = "AZ-CI-002") -> RuleEvaluation:
    return _make_evaluation(
        rule_id=rule_id,
        status=EvaluationStatus.UNKNOWN,
        reason_code="WORKFLOWS_UNAVAILABLE",
        reason="GitHub API did not return workflow list.",
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_pool():
    """Patch _get_pool so CIDatabase never opens a real connection."""
    mock_conn = MagicMock()
    mock_conn.closed = False
    mock_cursor = MagicMock()
    mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cursor

    mock_pool_instance = MagicMock()
    mock_pool_instance.getconn.return_value = mock_conn
    mock_pool_instance.putconn.return_value = None

    with patch("api.models.ci_scan._get_pool", return_value=mock_pool_instance):
        yield mock_pool_instance, mock_conn, mock_cursor


# ---------------------------------------------------------------------------
# CIDatabase.connect / close
# ---------------------------------------------------------------------------


class TestCIDatabaseConnection:
    def test_connect_acquires_from_pool(self, mock_pool):
        pool, conn, _ = mock_pool
        db = CIDatabase(DSN)
        db.connect()
        pool.getconn.assert_called_once()
        assert db.conn is conn

    def test_close_returns_to_pool(self, mock_pool):
        pool, conn, _ = mock_pool
        db = CIDatabase(DSN)
        db.connect()
        db.close()
        pool.putconn.assert_called_once_with(conn, close=False)
        assert db.conn is None

    def test_close_noop_when_not_connected(self, mock_pool):
        pool, _, _ = mock_pool
        db = CIDatabase(DSN)
        db.close()  # should not raise
        pool.putconn.assert_not_called()

    def test_missing_dsn_raises(self):
        with patch.dict("os.environ", {}, clear=True):
            # Ensure DATABASE_URL is absent
            import os
            os.environ.pop("DATABASE_URL", None)
            with pytest.raises(RuntimeError, match="DSN or DATABASE_URL"):
                CIDatabase("")


# ---------------------------------------------------------------------------
# CIDatabase.create_pending_ci_scan
# ---------------------------------------------------------------------------


class TestCreatePendingCIScan:
    def test_inserts_pending_row(self, mock_pool):
        _, conn, cursor = mock_pool
        db = CIDatabase(DSN)
        db.connect()
        db.create_pending_ci_scan(SCAN_ID, OWNER, REPO)

        sql_called = cursor.execute.call_args[0][0]
        assert "INSERT INTO ci_scans" in sql_called
        assert "'pending'" in sql_called
        conn.commit.assert_called_once()

    def test_passes_correct_params(self, mock_pool):
        _, _, cursor = mock_pool
        db = CIDatabase(DSN)
        db.connect()
        db.create_pending_ci_scan(SCAN_ID, OWNER, REPO)

        params = cursor.execute.call_args[0][1]
        assert params[0] == SCAN_ID
        assert params[1] == OWNER
        assert params[2] == REPO


# ---------------------------------------------------------------------------
# CIDatabase.save_ci_scan
# ---------------------------------------------------------------------------


class TestSaveCIScan:
    def _save(self, mock_pool, evaluations: List[Dict[str, Any]], **kwargs):
        _, conn, cursor = mock_pool
        # cursor.fetchone is not used in save_ci_scan but mock it anyway
        cursor.fetchone.return_value = None
        db = CIDatabase(DSN)
        db.connect()
        db.save_ci_scan(SCAN_ID, OWNER, REPO, evaluations, **kwargs)
        return conn, cursor

    def test_upserts_scan_header(self, mock_pool):
        conn, cursor = self._save(mock_pool, [])
        first_call_sql = cursor.execute.call_args_list[0][0][0]
        assert "INSERT INTO ci_scans" in first_call_sql
        assert "ON CONFLICT" in first_call_sql

    def test_deletes_stale_evaluations_before_insert(self, mock_pool):
        conn, cursor = self._save(mock_pool, [])
        delete_call = cursor.execute.call_args_list[1][0][0]
        assert "DELETE FROM ci_scan_evaluations" in delete_call

    def test_inserts_one_row_per_evaluation(self, mock_pool):
        evs = [
            _make_evaluation("AZ-CI-001").to_dict(),
            _fail_evaluation("AZ-CI-002").to_dict(),
        ]
        _, cursor = self._save(mock_pool, evs)
        insert_calls = [
            c for c in cursor.execute.call_args_list
            if "INSERT INTO ci_scan_evaluations" in c[0][0]
        ]
        assert len(insert_calls) == 2

    def test_fail_count_computed_correctly(self, mock_pool):
        evs = [
            _fail_evaluation("AZ-CI-001").to_dict(),
            _fail_evaluation("AZ-CI-002").to_dict(),
            _make_evaluation("AZ-CI-003").to_dict(),
        ]
        _, cursor = self._save(mock_pool, evs)
        header_params = cursor.execute.call_args_list[0][0][1]
        # fail_count is at index 7 in the INSERT params
        fail_count = header_params[7]
        assert fail_count == 2

    def test_status_is_completed_on_success(self, mock_pool):
        _, cursor = self._save(mock_pool, [])
        header_params = cursor.execute.call_args_list[0][0][1]
        status = header_params[5]
        assert status == "completed"

    def test_status_is_failed_when_error_message_set(self, mock_pool):
        _, cursor = self._save(mock_pool, [], error_message="boom")
        header_params = cursor.execute.call_args_list[0][0][1]
        status = header_params[5]
        assert status == "failed"

    def test_evidence_serialised_as_json(self, mock_pool):
        ev = _make_evaluation(evidence={"workflow_path": ".github/workflows/ci.yml"}).to_dict()
        _, cursor = self._save(mock_pool, [ev])
        insert_params = cursor.execute.call_args_list[2][0][1]
        evidence_json = insert_params[7]
        parsed = json.loads(evidence_json)
        assert parsed["workflow_path"] == ".github/workflows/ci.yml"

    def test_rollback_on_db_error(self, mock_pool):
        _, conn, cursor = mock_pool
        cursor.execute.side_effect = [None, Exception("db error")]
        db = CIDatabase(DSN)
        db.connect()
        with pytest.raises(Exception, match="db error"):
            db.save_ci_scan(SCAN_ID, OWNER, REPO, [])
        conn.rollback.assert_called_once()

    def test_commits_on_success(self, mock_pool):
        conn, _ = self._save(mock_pool, [])
        conn.commit.assert_called()


# ---------------------------------------------------------------------------
# CIDatabase.get_ci_scan / get_ci_scans / get_ci_scan_evaluations
# ---------------------------------------------------------------------------


class TestCIDatabaseRead:
    def test_get_ci_scan_returns_none_when_not_found(self, mock_pool):
        _, _, cursor = mock_pool
        cursor.fetchone.return_value = None
        db = CIDatabase(DSN)
        db.connect()
        result = db.get_ci_scan(SCAN_ID)
        assert result is None

    def test_get_ci_scan_returns_dict(self, mock_pool):
        _, _, cursor = mock_pool
        cursor.fetchone.return_value = {"scan_id": SCAN_ID, "owner": OWNER, "repo": REPO}
        db = CIDatabase(DSN)
        db.connect()
        result = db.get_ci_scan(SCAN_ID)
        assert result["scan_id"] == SCAN_ID

    def test_get_ci_scans_filters_by_owner_repo(self, mock_pool):
        _, _, cursor = mock_pool
        cursor.fetchall.return_value = []
        db = CIDatabase(DSN)
        db.connect()
        db.get_ci_scans(owner=OWNER, repo=REPO)
        sql = cursor.execute.call_args[0][0]
        assert "owner" in sql
        assert "repo" in sql

    def test_get_ci_scan_evaluations_ordered(self, mock_pool):
        _, _, cursor = mock_pool
        cursor.fetchall.return_value = []
        db = CIDatabase(DSN)
        db.connect()
        db.get_ci_scan_evaluations(SCAN_ID)
        sql = cursor.execute.call_args[0][0]
        assert "ORDER BY rule_id" in sql


# ---------------------------------------------------------------------------
# CIScanEngine.run_and_persist
# ---------------------------------------------------------------------------


class TestRunAndPersist:
    """Verify that run_and_persist() calls CIDatabase in the right order
    and propagates failures correctly. CIDatabase is patched at module level
    so no psycopg2 pool is needed here."""

    def _make_engine(self) -> CIScanEngine:
        engine = CIScanEngine(owner=OWNER, repo=REPO, dsn=DSN)
        return engine

    @patch("scanner.ci_engine.CIScanEngine.run_scan")
    @patch("scanner.ci_engine.CIDatabase")
    def test_happy_path_calls_db_in_order(self, MockDB, mock_run_scan):
        mock_db = MagicMock()
        MockDB.return_value = mock_db
        evaluations = [_make_evaluation(), _fail_evaluation()]
        mock_run_scan.return_value = evaluations

        engine = self._make_engine()
        returned_id, returned_evals = engine.run_and_persist(scan_id=SCAN_ID)

        assert returned_id == SCAN_ID
        assert returned_evals == evaluations

        mock_db.connect.assert_called_once()
        mock_db.create_pending_ci_scan.assert_called_once_with(SCAN_ID, OWNER, REPO)
        mock_db.update_ci_scan_status.assert_any_call(SCAN_ID, "running")
        mock_db.save_ci_scan.assert_called_once()
        mock_db.close.assert_called_once()

    @patch("scanner.ci_engine.CIScanEngine.run_scan")
    @patch("scanner.ci_engine.CIDatabase")
    def test_save_ci_scan_receives_dicts_not_objects(self, MockDB, mock_run_scan):
        mock_db = MagicMock()
        MockDB.return_value = mock_db
        ev = _make_evaluation()
        mock_run_scan.return_value = [ev]

        engine = self._make_engine()
        engine.run_and_persist(scan_id=SCAN_ID)

        evaluations_arg = mock_db.save_ci_scan.call_args.kwargs["evaluations"]
        assert isinstance(evaluations_arg, list)
        assert all(isinstance(e, dict) for e in evaluations_arg)

    @patch("scanner.ci_engine.CIScanEngine.run_scan")
    @patch("scanner.ci_engine.CIDatabase")
    def test_run_scan_failure_marks_scan_failed(self, MockDB, mock_run_scan):
        mock_db = MagicMock()
        MockDB.return_value = mock_db
        mock_run_scan.side_effect = RuntimeError("GitHub rate limit")

        engine = self._make_engine()
        with pytest.raises(RuntimeError, match="GitHub rate limit"):
            engine.run_and_persist(scan_id=SCAN_ID)

        mock_db.update_ci_scan_status.assert_any_call(
            SCAN_ID, "failed", error_message="GitHub rate limit"
        )
        mock_db.close.assert_called_once()

    @patch("scanner.ci_engine.CIDatabase")
    def test_missing_dsn_raises_before_db_call(self, MockDB):
        import os
        os.environ.pop("DATABASE_URL", None)
        engine = CIScanEngine(owner=OWNER, repo=REPO)  # no dsn
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(RuntimeError, match="DSN"):
                engine.run_and_persist(scan_id=SCAN_ID)
        MockDB.assert_not_called()

    @patch("scanner.ci_engine.CIScanEngine.run_scan")
    @patch("scanner.ci_engine.CIDatabase")
    def test_scan_id_generated_when_not_supplied(self, MockDB, mock_run_scan):
        mock_db = MagicMock()
        MockDB.return_value = mock_db
        mock_run_scan.return_value = []

        engine = self._make_engine()
        returned_id, _ = engine.run_and_persist()

        # A UUID4 was generated
        assert returned_id is not None
        uuid.UUID(returned_id)  # raises if not a valid UUID

    @patch("scanner.ci_engine.CIScanEngine.run_scan")
    @patch("scanner.ci_engine.CIDatabase")
    def test_close_called_even_when_status_update_fails(self, MockDB, mock_run_scan):
        """close() must be called in the finally block even when the
        error-path status update itself throws."""
        mock_db = MagicMock()
        MockDB.return_value = mock_db
        mock_run_scan.side_effect = RuntimeError("scan error")
        mock_db.update_ci_scan_status.side_effect = [None, RuntimeError("status error")]

        engine = self._make_engine()
        with pytest.raises(RuntimeError, match="scan error"):
            engine.run_and_persist(scan_id=SCAN_ID)

        mock_db.close.assert_called_once()
