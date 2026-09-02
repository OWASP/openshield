"""
tests/test_worker.py

Unit tests for scanner/worker.py.

These tests verify the worker's state machine and error handling logic
using mocks. No live database or Azure calls are made.
"""

import unittest
from unittest.mock import ANY, patch
from api.models.finding import LostLease
from scanner.worker import LeaseHeartbeat, POLL_INTERVAL_SECONDS, run_worker
import uuid


class StopWorker(BaseException):
    """Custom exception to break the infinite worker loop during tests."""

    pass


class OneHeartbeatThenStop:
    """Deterministically run one heartbeat loop iteration without sleeping."""

    def __init__(self):
        self.calls = 0

    def wait(self, _seconds):
        self.calls += 1
        return self.calls > 1

    def set(self):
        pass


class TestWorker(unittest.TestCase):
    def setUp(self):
        self.mock_db_url = "postgresql://user:pass@localhost/db"
        self.scan_id = str(uuid.uuid4())
        self.subscription_id = "00000000-0000-0000-0000-000000000000"

    @patch("scanner.worker.DatabaseManager")
    @patch("scanner.worker.ScanEngine")
    @patch("scanner.worker.os.environ.get")
    @patch("scanner.worker.time.sleep")
    @patch("scanner.worker.LeaseHeartbeat")
    def test_worker_processes_pending_scan_successfully(
        self, mock_heartbeat_class, mock_sleep, mock_env, mock_engine_class, mock_db_class
    ):
        """
        Verify the happy path:
        1. Worker claims a pending scan atomically.
        2. Executes scan via ScanEngine.
        3. Saves findings and updates status to 'completed'.
        """
        mock_env.return_value = self.mock_db_url

        # Mock DB instance
        mock_db = mock_db_class.return_value

        # Mock Engine instance
        mock_engine = mock_engine_class.return_value
        mock_engine.run_scan.return_value = {
            "scan_id": self.scan_id,
            "subscription_id": self.subscription_id,
            "findings": [{"rule_id": "AZ-STOR-001"}],
            "total_findings": 1,
            "started_at": "2026-06-05T12:00:00Z",
        }

        # We need to stop the infinite loop. We'll raise StopWorker on the second call to recover_stale_scans.
        mock_db.recover_stale_scans.side_effect = [None, StopWorker()]
        mock_db.claim_next_enrichment_job.return_value = None
        mock_db.claim_next_pending_scan.side_effect = [
            {"scan_id": self.scan_id, "subscription_id": self.subscription_id, "fencing_token": 1},
            None,
        ]
        mock_heartbeat_class.return_value.lost.is_set.return_value = False

        with self.assertRaises(StopWorker):
            run_worker()

        # Verify state transitions
        mock_db.recover_stale_scans.assert_called()
        mock_db.claim_next_pending_scan.assert_called()
        mock_engine.run_scan.assert_called_once_with(self.scan_id)
        mock_db.save_scan.assert_called_once()

        # Check that result was marked completed before saving
        saved_result = mock_db.save_scan.call_args[0][0]
        self.assertEqual(saved_result["status"], "completed")
        self.assertIn("completed_at", saved_result)
        self.assertEqual(mock_db.save_scan.call_args[0][2], 1)
        self.assertGreaterEqual(mock_heartbeat_class.return_value.stop.call_count, 1)

    @patch("scanner.worker.DatabaseManager")
    @patch("scanner.worker.ScanEngine")
    @patch("scanner.worker.os.environ.get")
    @patch("scanner.worker.time.sleep")
    @patch("scanner.worker.LeaseHeartbeat")
    def test_worker_handles_scan_failure_gracefully(
        self, mock_heartbeat_class, mock_sleep, mock_env, mock_engine_class, mock_db_class
    ):
        """
        Verify the error path:
        1. Worker claims a pending scan.
        2. ScanEngine raises an exception.
        3. Worker catches it and marks the scan as 'failed' with a sanitized error message.
        """
        mock_env.return_value = self.mock_db_url
        mock_db = mock_db_class.return_value

        mock_db.recover_stale_scans.side_effect = [None, StopWorker()]
        mock_db.claim_next_enrichment_job.return_value = None
        mock_db.claim_next_pending_scan.side_effect = [
            {"scan_id": self.scan_id, "subscription_id": self.subscription_id, "fencing_token": 1},
            None,
        ]
        mock_heartbeat_class.return_value.lost.is_set.return_value = False

        # Mock Engine to fail
        mock_engine = mock_engine_class.return_value
        mock_engine.run_scan.side_effect = RuntimeError("Azure Authentication Failed")

        with self.assertRaises(StopWorker):
            run_worker()

        # Verify status was updated to failed with sanitized message
        mock_db.update_scan_status.assert_any_call(
            self.scan_id,
            "failed",
            error_message="An internal error occurred during the scan. Please check the logs.",
            lease_owner=ANY,
            fencing_token=1,
        )
        # Ensure findings were NOT saved on failure
        mock_db.save_scan.assert_not_called()
        self.assertGreaterEqual(mock_heartbeat_class.return_value.stop.call_count, 1)

    @patch("scanner.worker.DatabaseManager")
    @patch("scanner.worker.ScanEngine")
    @patch("scanner.worker.os.environ.get")
    @patch("scanner.worker.time.sleep")
    @patch("scanner.worker.LeaseHeartbeat")
    def test_worker_does_not_persist_after_heartbeat_reports_lost_lease(
        self, mock_heartbeat_class, mock_sleep, mock_env, mock_engine_class, mock_db_class
    ):
        mock_env.return_value = self.mock_db_url
        mock_db = mock_db_class.return_value
        mock_db.recover_stale_scans.side_effect = [None, StopWorker()]
        mock_db.claim_next_enrichment_job.return_value = None
        mock_db.claim_next_pending_scan.return_value = {
            "scan_id": self.scan_id,
            "subscription_id": self.subscription_id,
            "fencing_token": 1,
        }
        mock_engine_class.return_value.run_scan.return_value = {
            "scan_id": self.scan_id,
            "subscription_id": self.subscription_id,
            "findings": [],
        }
        mock_heartbeat_class.return_value.lost.is_set.return_value = True

        with self.assertRaises(StopWorker):
            run_worker()

        mock_db.save_scan.assert_not_called()
        mock_db.update_scan_status.assert_not_called()


@patch("scanner.worker.DatabaseManager")
def test_heartbeat_uses_and_closes_a_dedicated_database_manager(mock_db_class):
    heartbeat = LeaseHeartbeat("postgresql://heartbeat-test/db", "scan-1", "worker-a", 7, 120, 1)
    heartbeat._stop = OneHeartbeatThenStop()

    heartbeat._run()

    mock_db_class.assert_called_once_with("postgresql://heartbeat-test/db")
    mock_db_class.return_value.heartbeat_scan.assert_called_once_with("scan-1", "worker-a", 7, 120)
    mock_db_class.return_value.close.assert_called_once()
    assert not heartbeat.lost.is_set()


@patch("scanner.worker.DatabaseManager")
def test_heartbeat_surfaces_lost_lease_and_closes_its_connection(mock_db_class):
    mock_db_class.return_value.heartbeat_scan.side_effect = LostLease("stale")
    heartbeat = LeaseHeartbeat("postgresql://heartbeat-test/db", "scan-1", "worker-a", 7, 120, 1)
    heartbeat._stop = OneHeartbeatThenStop()

    heartbeat._run()

    assert heartbeat.lost.is_set()
    mock_db_class.return_value.close.assert_called_once()

    @patch("scanner.worker.DatabaseManager")
    @patch("scanner.worker.os.environ.get")
    @patch("scanner.worker.time.sleep")
    def test_worker_sleeps_when_no_scans_pending(self, mock_sleep, mock_env, mock_db_class):
        """Verify that the worker waits when the queue is empty."""
        mock_env.return_value = self.mock_db_url
        mock_db = mock_db_class.return_value

        mock_db.recover_stale_scans.side_effect = [None, StopWorker()]
        mock_db.claim_next_enrichment_job.return_value = None
        mock_db.claim_next_pending_scan.return_value = None

        with self.assertRaises(StopWorker):
            run_worker()

        mock_sleep.assert_called_with(POLL_INTERVAL_SECONDS)

    @patch("scanner.worker.process_enrichment_job")
    @patch("scanner.worker.DatabaseManager")
    @patch("scanner.worker.ScanEngine")
    @patch("scanner.worker.os.environ.get")
    @patch("scanner.worker.time.sleep")
    @patch("scanner.worker.LeaseHeartbeat")
    def test_enrichment_backlog_does_not_starve_pending_scans(
        self, mock_heartbeat_class, mock_sleep, mock_env, mock_engine_class, mock_db_class, mock_process
    ):
        """With both queues permanently backlogged, each still gets served.

        Draining enrichment and restarting the loop would mean a scan is never
        claimed while enrichment work keeps arriving.
        """
        mock_env.return_value = self.mock_db_url
        mock_db = mock_db_class.return_value
        mock_engine_class.return_value.run_scan.return_value = {
            "scan_id": self.scan_id,
            "subscription_id": self.subscription_id,
            "findings": [],
            "started_at": "2026-06-05T12:00:00Z",
        }
        mock_heartbeat_class.return_value.lost.is_set.return_value = False

        # Both queues always have work; stop after two full iterations.
        mock_db.recover_stale_scans.side_effect = [None, None, StopWorker()]
        mock_db.claim_next_enrichment_job.return_value = {"job_id": "job-1", "scan_id": self.scan_id}
        mock_db.claim_next_pending_scan.return_value = {
            "scan_id": self.scan_id,
            "subscription_id": self.subscription_id,
            "fencing_token": 1,
        }

        with self.assertRaises(StopWorker):
            run_worker()

        # Each iteration served one job from each queue -- neither starved.
        self.assertEqual(mock_process.call_count, 2)
        self.assertEqual(mock_db.save_scan.call_count, 2)
        # A busy worker never idles.
        mock_sleep.assert_not_called()

    @patch("scanner.worker.process_enrichment_job")
    @patch("scanner.worker.DatabaseManager")
    @patch("scanner.worker.os.environ.get")
    @patch("scanner.worker.time.sleep")
    def test_enrichment_only_backlog_polls_again_without_idling(
        self, mock_sleep, mock_env, mock_db_class, mock_process
    ):
        """Enrichment work must not be paced by the empty-queue poll interval."""
        mock_env.return_value = self.mock_db_url
        mock_db = mock_db_class.return_value
        mock_db.recover_stale_scans.side_effect = [None, StopWorker()]
        mock_db.claim_next_enrichment_job.return_value = {"job_id": "job-1", "scan_id": self.scan_id}
        mock_db.claim_next_pending_scan.return_value = None

        with self.assertRaises(StopWorker):
            run_worker()

        mock_process.assert_called_once()
        mock_sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
