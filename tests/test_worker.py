"""
tests/test_worker.py

Unit tests for scanner/worker.py.

These tests verify the worker's state machine and error handling logic
using mocks. No live database or Azure calls are made.
"""

import unittest
from unittest.mock import ANY, patch
from scanner.worker import run_worker, POLL_INTERVAL_SECONDS
import uuid


class StopWorker(BaseException):
    """Custom exception to break the infinite worker loop during tests."""

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

    @patch("scanner.worker.DatabaseManager")
    @patch("scanner.worker.os.environ.get")
    @patch("scanner.worker.time.sleep")
    def test_worker_sleeps_when_no_scans_pending(self, mock_sleep, mock_env, mock_db_class):
        """Verify that the worker waits when the queue is empty."""
        mock_env.return_value = self.mock_db_url
        mock_db = mock_db_class.return_value

        mock_db.recover_stale_scans.side_effect = [None, StopWorker()]
        mock_db.claim_next_pending_scan.return_value = None

        with self.assertRaises(StopWorker):
            run_worker()

        mock_sleep.assert_called_with(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    unittest.main()
