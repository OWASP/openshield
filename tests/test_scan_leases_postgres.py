"""PostgreSQL-backed lease, fencing, and connection-recovery tests."""

import os
import threading
import uuid
from datetime import datetime, timezone

import psycopg2
from psycopg2 import extensions
import pytest

from api.models.finding import DatabaseManager, LostLease


pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="DATABASE_URL is required for PostgreSQL tests"
)


def _result(scan_id: str, subscription_id: str) -> dict:
    return {
        "scan_id": scan_id,
        "subscription_id": subscription_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "findings": [
            {
                "rule_id": "AZ-LEASE-001",
                "rule_name": "Lease test finding",
                "severity": "HIGH",
                "category": "Test",
                "resource_id": f"/subscriptions/{subscription_id}/resourceGroups/test/providers/Test/resource",
                "resource_name": "resource",
                "resource_type": "Test/resource",
                "description": "Lease test finding",
                "remediation": "Fix the test resource",
                "frameworks": {},
                "metadata": {},
                "detected_at": datetime.now(timezone.utc).isoformat(),
            }
        ],
    }


class ScanRows:
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.scan_ids: list[str] = []

    def create(self) -> tuple[str, str]:
        scan_id = str(uuid.uuid4())
        subscription_id = str(uuid.uuid4())
        db = DatabaseManager(self.dsn)
        try:
            db.create_pending_scan(scan_id, subscription_id)
        finally:
            db.close()
        self.scan_ids.append(scan_id)
        return scan_id, subscription_id

    def expire(self, scan_id: str) -> None:
        with psycopg2.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE scans SET lease_expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second' WHERE scan_id = %s",
                    (scan_id,),
                )

    def scan(self, scan_id: str) -> dict:
        db = DatabaseManager(self.dsn)
        try:
            scan = db.get_scan(scan_id)
            assert scan is not None
            return scan
        finally:
            db.close()

    def finding_count(self, scan_id: str) -> int:
        with psycopg2.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM findings WHERE scan_id = %s", (scan_id,))
                return cur.fetchone()[0]

    def rearm(self, scan_id: str, owner: str, fencing_token: int) -> None:
        """Simulate duplicate delivery of the same claimed result for persistence tests."""
        with psycopg2.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scans
                    SET status = 'running', completed_at = NULL, lease_owner = %s,
                        fencing_token = %s, lease_expires_at = CURRENT_TIMESTAMP + INTERVAL '5 minutes'
                    WHERE scan_id = %s
                    """,
                    (owner, fencing_token, scan_id),
                )

    def evaluation_count(self, scan_id: str) -> int:
        with psycopg2.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM rule_evaluations WHERE scan_id = %s", (scan_id,))
                return cur.fetchone()[0]

    def cleanup(self) -> None:
        with psycopg2.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                for scan_id in self.scan_ids:
                    cur.execute("DELETE FROM rule_evaluations WHERE scan_id = %s", (scan_id,))
                    cur.execute("DELETE FROM findings WHERE scan_id = %s", (scan_id,))
                    cur.execute("DELETE FROM scans WHERE scan_id = %s", (scan_id,))


@pytest.fixture
def scan_rows() -> ScanRows:
    rows = ScanRows(os.environ["DATABASE_URL"])
    yield rows
    rows.cleanup()


def _claim(dsn: str, owner: str) -> dict | None:
    db = DatabaseManager(dsn)
    try:
        return db.claim_next_pending_scan(owner, 120)
    finally:
        db.close()


def _recover(dsn: str, max_attempts: int = 3) -> int:
    db = DatabaseManager(dsn)
    try:
        return db.recover_stale_scans(max_attempts=max_attempts)
    finally:
        db.close()


def test_two_workers_race_to_claim_only_one_scan(scan_rows):
    scan_rows.create()
    barrier = threading.Barrier(2)
    claims: list[dict | None] = []

    def claim(owner: str) -> None:
        barrier.wait()
        claims.append(_claim(scan_rows.dsn, owner))

    threads = [threading.Thread(target=claim, args=(owner,)) for owner in ("worker-a", "worker-b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    successful = [claim for claim in claims if claim is not None]
    assert len(successful) == 1
    assert successful[0]["lease_owner"] in {"worker-a", "worker-b"}
    assert successful[0]["fencing_token"] == 1


def test_active_lease_cannot_be_reclaimed(scan_rows):
    scan_rows.create()
    assert _claim(scan_rows.dsn, "worker-a") is not None
    assert _claim(scan_rows.dsn, "worker-b") is None


def test_heartbeat_extends_current_lease_without_changing_owner_or_token(scan_rows):
    scan_id, _ = scan_rows.create()
    claim = _claim(scan_rows.dsn, "worker-a")
    assert claim is not None

    db = DatabaseManager(scan_rows.dsn)
    try:
        renewed = db.heartbeat_scan(scan_id, "worker-a", claim["fencing_token"], 600)
    finally:
        db.close()

    assert renewed["lease_owner"] == "worker-a"
    assert renewed["fencing_token"] == claim["fencing_token"]
    assert renewed["lease_expires_at"] > claim["lease_expires_at"]


def test_expired_lease_is_reclaimed_with_new_fencing_token(scan_rows):
    scan_id, _ = scan_rows.create()
    first_claim = _claim(scan_rows.dsn, "worker-a")
    assert first_claim is not None
    scan_rows.expire(scan_id)

    assert _recover(scan_rows.dsn) == 1
    second_claim = _claim(scan_rows.dsn, "worker-b")

    assert second_claim is not None
    assert second_claim["lease_owner"] == "worker-b"
    assert second_claim["fencing_token"] > first_claim["fencing_token"]


def test_stale_worker_cannot_heartbeat_complete_fail_or_write_results(scan_rows):
    scan_id, subscription_id = scan_rows.create()
    first_claim = _claim(scan_rows.dsn, "worker-a")
    assert first_claim is not None
    scan_rows.expire(scan_id)
    _recover(scan_rows.dsn)
    second_claim = _claim(scan_rows.dsn, "worker-b")
    assert second_claim is not None

    stale_db = DatabaseManager(scan_rows.dsn)
    try:
        with pytest.raises(LostLease):
            stale_db.heartbeat_scan(scan_id, "worker-a", first_claim["fencing_token"], 120)
        with pytest.raises(LostLease):
            stale_db.update_scan_status(
                scan_id,
                "failed",
                "stale worker failure",
                lease_owner="worker-a",
                fencing_token=first_claim["fencing_token"],
            )
        with pytest.raises(LostLease):
            stale_db.save_scan(_result(scan_id, subscription_id), "worker-a", first_claim["fencing_token"])
    finally:
        stale_db.close()

    assert scan_rows.finding_count(scan_id) == 0
    scan = scan_rows.scan(scan_id)
    assert scan["status"] == "running"
    assert scan["lease_owner"] == "worker-b"
    assert scan["fencing_token"] == second_claim["fencing_token"]


def test_current_owner_completion_persists_results_atomically(scan_rows):
    scan_id, subscription_id = scan_rows.create()
    claim = _claim(scan_rows.dsn, "worker-b")
    assert claim is not None

    db = DatabaseManager(scan_rows.dsn)
    try:
        db.save_scan(_result(scan_id, subscription_id), "worker-b", claim["fencing_token"])
    finally:
        db.close()

    scan = scan_rows.scan(scan_id)
    assert scan["status"] == "completed"
    assert scan["lease_owner"] is None
    assert scan_rows.finding_count(scan_id) == 1


def test_sql_abort_rolls_back_and_the_connection_remains_usable(scan_rows):
    scan_id, subscription_id = scan_rows.create()
    claim = _claim(scan_rows.dsn, "worker-a")
    assert claim is not None
    broken_result = _result(scan_id, subscription_id)
    broken_result["findings"][0]["detected_at"] = None

    db = DatabaseManager(scan_rows.dsn)
    try:
        with pytest.raises(psycopg2.Error):
            db.save_scan(broken_result, "worker-a", claim["fencing_token"])
        db.update_scan_status(
            scan_id,
            "failed",
            "controlled SQL failure",
            lease_owner="worker-a",
            fencing_token=claim["fencing_token"],
        )
    finally:
        db.close()

    assert scan_rows.scan(scan_id)["status"] == "failed"
    assert scan_rows.finding_count(scan_id) == 0


def test_terminated_backend_is_discarded_and_reacquired(scan_rows):
    scan_id, _ = scan_rows.create()
    db = DatabaseManager(scan_rows.dsn)
    try:
        conn = db._get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT pg_backend_pid()")
            backend_pid = cur.fetchone()[0]
        conn.commit()

        with psycopg2.connect(scan_rows.dsn) as terminator:
            with terminator.cursor() as cur:
                cur.execute("SELECT pg_terminate_backend(%s)", (backend_pid,))
                assert cur.fetchone()[0] is True

        with pytest.raises(psycopg2.OperationalError):
            db.ping()
        db.rollback()

        replacement = db._get_conn()
        with replacement.cursor() as cur:
            cur.execute("SELECT pg_backend_pid()")
            assert cur.fetchone()[0] != backend_pid
        db.rollback()
        assert db.get_scan(scan_id) is not None
    finally:
        db.close()


def test_expired_restart_work_obeys_attempt_limit(scan_rows):
    scan_id, _ = scan_rows.create()
    assert _claim(scan_rows.dsn, "worker-a") is not None
    scan_rows.expire(scan_id)
    assert _recover(scan_rows.dsn, max_attempts=3) == 1

    assert _claim(scan_rows.dsn, "worker-b") is not None
    scan_rows.expire(scan_id)
    assert _recover(scan_rows.dsn, max_attempts=3) == 1

    assert _claim(scan_rows.dsn, "worker-c") is not None
    scan_rows.expire(scan_id)
    assert _recover(scan_rows.dsn, max_attempts=3) == 1
    assert scan_rows.scan(scan_id)["status"] == "failed"


def test_empty_claim_leaves_no_open_transaction(scan_rows):
    db = DatabaseManager(scan_rows.dsn)
    try:
        assert db.claim_next_pending_scan("worker-a", 120) is None
        assert db._get_conn().info.transaction_status == extensions.TRANSACTION_STATUS_IDLE
    finally:
        db.close()


def test_duplicate_result_delivery_upserts_mutable_fields_and_evaluations(scan_rows):
    scan_id, subscription_id = scan_rows.create()
    claim = _claim(scan_rows.dsn, "worker-a")
    assert claim is not None
    result = _result(scan_id, subscription_id)
    result["evaluations"] = [
        {
            "rule_id": "AZ-LEASE-001",
            "resource_id": result["findings"][0]["resource_id"],
            "resource_type": "Test/resource",
            "status": "FAIL",
            "evidence": {"version": 1},
        }
    ]

    db = DatabaseManager(scan_rows.dsn)
    try:
        db.save_scan(result, "worker-a", claim["fencing_token"])
        first_id = db.get_findings({"scan_id": scan_id})[0]["id"]
        scan_rows.rearm(scan_id, "worker-a", claim["fencing_token"])
        result["findings"][0]["description"] = "Updated presentation text"
        result["findings"][0]["severity"] = "CRITICAL"
        result["evaluations"][0]["evidence"] = {"version": 2}
        db.save_scan(result, "worker-a", claim["fencing_token"])
        persisted = db.get_findings({"scan_id": scan_id})
    finally:
        db.close()

    assert len(persisted) == 1
    assert persisted[0]["id"] == first_id
    assert persisted[0]["description"] == "Updated presentation text"
    assert persisted[0]["severity"] == "CRITICAL"
    assert scan_rows.evaluation_count(scan_id) == 1


def test_distinct_finding_discriminators_preserve_multiple_violations(scan_rows):
    scan_id, subscription_id = scan_rows.create()
    claim = _claim(scan_rows.dsn, "worker-a")
    assert claim is not None
    result = _result(scan_id, subscription_id)
    duplicate_scope = dict(result["findings"][0])
    result["findings"][0]["finding_discriminator"] = "network-rule-a"
    duplicate_scope["finding_discriminator"] = "network-rule-b"
    duplicate_scope["description"] = "A second violation on the same resource"
    result["findings"].append(duplicate_scope)

    db = DatabaseManager(scan_rows.dsn)
    try:
        db.save_scan(result, "worker-a", claim["fencing_token"])
    finally:
        db.close()

    assert scan_rows.finding_count(scan_id) == 2
