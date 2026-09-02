"""PostgreSQL lease, retry, and resume tests for durable enrichment jobs."""

import os
import threading
import uuid
from unittest.mock import patch

import psycopg2
import psycopg2.extras
import pytest

from api.models.finding import DatabaseManager, LostLease
from scanner.enrichment_worker import process_enrichment_job


pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="DATABASE_URL is required for PostgreSQL tests"
)


@pytest.fixture
def enrichment_scan():
    dsn = os.environ["DATABASE_URL"]
    scan_id, subscription_id = str(uuid.uuid4()), str(uuid.uuid4())
    db = DatabaseManager(dsn)
    try:
        db.create_pending_scan(scan_id, subscription_id)
        # Claim this scan explicitly. An unrestricted claim takes the globally
        # oldest pending scan, which in a shared test database is very often a
        # row another test admitted first.
        claim = db.claim_next_pending_scan("seed", 120, scan_id=scan_id)
        assert claim is not None and str(claim["scan_id"]) == scan_id
        result = {
            "scan_id": scan_id,
            "subscription_id": subscription_id,
            "findings": [
                {
                    "rule_id": "AZ-STOR-001",
                    "rule_name": "test",
                    "severity": "HIGH",
                    "resource_id": f"/subscriptions/{subscription_id}/resources/one",
                    "resource_name": "one",
                    "resource_type": "Test/resource",
                    "detected_at": "2026-08-29T00:00:00+00:00",
                },
                {
                    "rule_id": "AZ-STOR-001",
                    "rule_name": "test",
                    "severity": "HIGH",
                    "resource_id": f"/subscriptions/{subscription_id}/resources/two",
                    "resource_name": "two",
                    "resource_type": "Test/resource",
                    "detected_at": "2026-08-29T00:00:00+00:00",
                },
            ],
        }
        db.save_scan(result, "seed", claim["fencing_token"])
        job, outcome = db.enqueue_enrichment_job(scan_id)
        assert outcome == "active"
        yield dsn, scan_id, job
    finally:
        db.close()
        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM enrichment_jobs WHERE scan_id = %s", (scan_id,))
                cur.execute("DELETE FROM findings WHERE scan_id = %s", (scan_id,))
                cur.execute("DELETE FROM scans WHERE scan_id = %s", (scan_id,))


def _claim(dsn, scan_id, owner="worker-a"):
    """Claim this scan's enrichment job, never another test's."""
    db = DatabaseManager(dsn)
    try:
        return db.claim_next_enrichment_job(owner, 120, scan_id=scan_id)
    finally:
        db.close()


def test_duplicate_enqueue_and_claim_race(enrichment_scan):
    dsn, scan_id, first_job = enrichment_scan
    db = DatabaseManager(dsn)
    try:
        replay, outcome = db.enqueue_enrichment_job(scan_id)
    finally:
        db.close()
    assert outcome == "active"
    assert replay["job_id"] == first_job["job_id"]

    barrier = threading.Barrier(2)
    claims = []

    def claim():
        barrier.wait()
        claims.append(_claim(dsn, scan_id))

    threads = [threading.Thread(target=claim) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len([job for job in claims if job]) == 1


def test_checkpoint_resume_and_completion(enrichment_scan):
    dsn, scan_id, _ = enrichment_scan
    job = _claim(dsn, scan_id)
    assert job is not None
    db = DatabaseManager(dsn)
    try:
        with patch("scanner.enrichment_worker.enrich_finding_durable") as enrich:
            calls = 0

            def enrich_once_then_fail(finding):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise RuntimeError("transient NVD failure")
                return {**finding, "cve_references": [{"cve_id": "CVE-1"}]}

            enrich.side_effect = enrich_once_then_fail
            assert process_enrichment_job(db, job, "worker-a", 120) == "retry"
        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT status, checkpoint FROM enrichment_jobs WHERE scan_id = %s", (scan_id,))
                assert cur.fetchone() == ("pending", 1)
                cur.execute(
                    "UPDATE enrichment_jobs SET next_retry_at = CURRENT_TIMESTAMP WHERE scan_id = %s", (scan_id,)
                )
        resumed = db.claim_next_enrichment_job("worker-b", 120, scan_id=scan_id)
        with patch("scanner.enrichment_worker.enrich_finding_durable") as enrich:
            enrich.side_effect = lambda finding: {**finding, "cve_references": [{"cve_id": "CVE-1"}]}
            assert process_enrichment_job(db, resumed, "worker-b", 120) == "completed"
        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT status, checkpoint FROM enrichment_jobs WHERE scan_id = %s", (scan_id,))
                assert cur.fetchone() == ("completed", 2)
                cur.execute(
                    "SELECT COUNT(*) FROM findings WHERE scan_id = %s AND cve_references <> '[]'::jsonb", (scan_id,)
                )
                assert cur.fetchone()[0] == 2
    finally:
        db.close()


def test_enrichment_retry_limit_becomes_terminal(enrichment_scan):
    dsn, scan_id, _ = enrichment_scan
    db = DatabaseManager(dsn)
    try:
        for attempt in range(1, 4):
            job = db.claim_next_enrichment_job("worker-a", 120, scan_id=scan_id)
            assert job is not None
            with patch("scanner.enrichment_worker.enrich_finding_durable", side_effect=RuntimeError("NVD unavailable")):
                expected = "failed" if attempt == 3 else "retry"
                assert process_enrichment_job(db, job, "worker-a", 120) == expected
            if attempt < 3:
                with psycopg2.connect(dsn) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE enrichment_jobs SET next_retry_at = CURRENT_TIMESTAMP WHERE scan_id = %s",
                            (scan_id,),
                        )
        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT status FROM enrichment_jobs WHERE scan_id = %s", (scan_id,))
                assert cur.fetchone()[0] == "failed"
    finally:
        db.close()


def test_expired_job_is_recovered_with_new_token_and_stale_owner_is_rejected(enrichment_scan):
    dsn, scan_id, _ = enrichment_scan
    first = _claim(dsn, scan_id)
    assert first is not None
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE enrichment_jobs
                SET lease_expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'
                WHERE scan_id = %s
                """,
                (scan_id,),
            )
    db = DatabaseManager(dsn)
    try:
        # Other tests may share this database; assert this job specifically
        # was recovered rather than that it was the only one.
        assert db.recover_stale_enrichment_jobs() >= 1
        second = db.claim_next_enrichment_job("worker-b", 120, scan_id=scan_id)
        assert second["fencing_token"] > first["fencing_token"]
        with pytest.raises(LostLease):
            db.heartbeat_enrichment_job(str(first["job_id"]), "worker-a", first["fencing_token"], 120)
    finally:
        db.close()


def _fail_terminally(dsn, db, scan_id):
    """Drive a job through its whole retry budget until it is 'failed'."""
    for attempt in range(1, 4):
        job = db.claim_next_enrichment_job("worker-a", 120, scan_id=scan_id)
        assert job is not None
        with patch("scanner.enrichment_worker.enrich_finding_durable", side_effect=RuntimeError("NVD unavailable")):
            process_enrichment_job(db, job, "worker-a", 120)
        if attempt < 3:
            with psycopg2.connect(dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE enrichment_jobs SET next_retry_at = CURRENT_TIMESTAMP WHERE scan_id = %s",
                        (scan_id,),
                    )
    return _job_row(dsn, scan_id)


def _job_row(dsn, scan_id):
    with psycopg2.connect(dsn) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM enrichment_jobs WHERE scan_id = %s", (scan_id,))
            return dict(cur.fetchone())


def test_terminally_failed_job_can_be_explicitly_requeued(enrichment_scan):
    dsn, scan_id, first_job = enrichment_scan
    db = DatabaseManager(dsn)
    try:
        failed = _fail_terminally(dsn, db, scan_id)
        assert failed["status"] == "failed"
        assert failed["attempt_count"] >= 3

        job, outcome = db.enqueue_enrichment_job(scan_id)
    finally:
        db.close()

    assert outcome == "requeued"
    # Same logical job, now retryable again.
    assert str(job["job_id"]) == str(first_job["job_id"])
    assert job["status"] == "pending"
    assert job["attempt_count"] == 0
    assert job["lease_owner"] is None
    assert job["lease_expires_at"] is None
    assert job["completed_at"] is None
    # The failure reason is kept as the audit trail, and the checkpoint is kept
    # so the retry resumes instead of re-enriching what already succeeded.
    assert job["error_message"]
    assert job["checkpoint"] == failed["checkpoint"]
    assert _job_row(dsn, scan_id)["next_retry_at"] is not None


def test_completed_job_is_never_restarted(enrichment_scan):
    dsn, scan_id, _ = enrichment_scan
    db = DatabaseManager(dsn)
    try:
        job = db.claim_next_enrichment_job("worker-a", 120, scan_id=scan_id)
        with patch("scanner.enrichment_worker.enrich_finding_durable") as enrich:
            enrich.side_effect = lambda finding: {**finding, "cve_references": [{"cve_id": "CVE-1"}]}
            assert process_enrichment_job(db, job, "worker-a", 120) == "completed"

        requeued, outcome = db.enqueue_enrichment_job(scan_id)
    finally:
        db.close()

    assert outcome == "completed"
    assert requeued["status"] == "completed"
    assert _job_row(dsn, scan_id)["status"] == "completed"


def test_requeue_does_not_steal_a_valid_running_lease(enrichment_scan):
    dsn, scan_id, _ = enrichment_scan
    db = DatabaseManager(dsn)
    try:
        running = db.claim_next_enrichment_job("worker-a", 120, scan_id=scan_id)
        assert running is not None

        job, outcome = db.enqueue_enrichment_job(scan_id)
        assert outcome == "active"
        assert job["status"] == "running"

        # The live owner keeps its lease and can still heartbeat and complete.
        db.heartbeat_enrichment_job(str(running["job_id"]), "worker-a", running["fencing_token"], 120)
        after = _job_row(dsn, scan_id)
        assert after["lease_owner"] == "worker-a"
        assert after["fencing_token"] == running["fencing_token"]
    finally:
        db.close()


def test_concurrent_requeues_converge_on_one_logical_job(enrichment_scan):
    dsn, scan_id, first_job = enrichment_scan
    db = DatabaseManager(dsn)
    try:
        _fail_terminally(dsn, db, scan_id)
    finally:
        db.close()

    barrier = threading.Barrier(4)
    outcomes: list[str] = []

    def requeue() -> None:
        worker_db = DatabaseManager(dsn)
        try:
            barrier.wait()
            outcomes.append(worker_db.enqueue_enrichment_job(scan_id)[1])
        finally:
            worker_db.close()

    threads = [threading.Thread(target=requeue) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # Exactly one caller performs the failed -> pending transition; the rest
    # observe the job that is already queued. Nobody creates a second job.
    assert sorted(outcomes) == ["active", "active", "active", "requeued"]
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM enrichment_jobs WHERE scan_id = %s", (scan_id,))
            assert cur.fetchone()[0] == 1
    assert str(_job_row(dsn, scan_id)["job_id"]) == str(first_job["job_id"])


def test_stale_token_cannot_write_after_requeue_and_reclaim(enrichment_scan):
    dsn, scan_id, _ = enrichment_scan
    db = DatabaseManager(dsn)
    try:
        # worker-a held the job through its last failed attempt; that is the
        # token a stale process would still be carrying.
        failed = _fail_terminally(dsn, db, scan_id)
        stale_job_id, stale_token = str(failed["job_id"]), failed["fencing_token"]

        assert db.enqueue_enrichment_job(scan_id)[1] == "requeued"
        reclaimed = db.claim_next_enrichment_job("worker-b", 120, scan_id=scan_id)
        assert reclaimed is not None
        assert reclaimed["fencing_token"] > stale_token

        findings = db.get_enrichment_findings(scan_id)
        with pytest.raises(LostLease):
            db.heartbeat_enrichment_job(stale_job_id, "worker-a", stale_token, 120)
        with pytest.raises(LostLease):
            db.persist_enrichment_progress(stale_job_id, "worker-a", stale_token, findings[0], 99)
        with pytest.raises(LostLease):
            db.complete_enrichment_job(stale_job_id, "worker-a", stale_token)

        # None of the rejected writes landed.
        current = _job_row(dsn, scan_id)
        assert current["checkpoint"] != 99
        assert current["status"] == "running"
        assert current["lease_owner"] == "worker-b"
    finally:
        db.close()


def test_requeued_job_can_eventually_complete(enrichment_scan):
    dsn, scan_id, _ = enrichment_scan
    db = DatabaseManager(dsn)
    try:
        _fail_terminally(dsn, db, scan_id)
        _, outcome = db.enqueue_enrichment_job(scan_id)
        assert outcome == "requeued"

        job = db.claim_next_enrichment_job("worker-b", 120, scan_id=scan_id)
        assert job is not None
        with patch("scanner.enrichment_worker.enrich_finding_durable") as enrich:
            enrich.side_effect = lambda finding: {**finding, "cve_references": [{"cve_id": "CVE-2"}]}
            assert process_enrichment_job(db, job, "worker-b", 120) == "completed"
    finally:
        db.close()

    assert _job_row(dsn, scan_id)["status"] == "completed"
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT cve_enrichment_status FROM scans WHERE scan_id = %s", (scan_id,))
            assert cur.fetchone()[0] == "COMPLETED"
