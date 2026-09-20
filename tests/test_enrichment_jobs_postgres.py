"""PostgreSQL lease, retry, and resume tests for durable enrichment jobs."""

import os
import threading
import time
import uuid
from contextlib import contextmanager
from unittest.mock import patch

import psycopg2
import psycopg2.extras
import pytest
from alembic import command
from alembic.config import Config

from api.models.finding import DatabaseManager, LostLease
from scanner.enrichment_worker import process_enrichment_job


pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="DATABASE_URL is required for PostgreSQL tests"
)

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@contextmanager
def _isolated_database():
    """Create a migrated database whose recovery count has no external rows."""
    base = os.environ["DATABASE_URL"].rsplit("/", 1)[0]
    name = f"openshield_enrichment_{uuid.uuid4().hex[:12]}"
    admin = psycopg2.connect(f"{base}/postgres")
    admin.autocommit = True
    try:
        with admin.cursor() as cur:
            cur.execute(f'CREATE DATABASE "{name}"')
        dsn = f"{base}/{name}"
        config = Config()
        config.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
        previous = os.environ.get("DATABASE_URL")
        os.environ["DATABASE_URL"] = dsn
        try:
            command.upgrade(config, "head")
        finally:
            if previous is None:
                os.environ.pop("DATABASE_URL", None)
            else:
                os.environ["DATABASE_URL"] = previous
        yield dsn
    finally:
        with admin.cursor() as cur:
            cur.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid()",
                (name,),
            )
            cur.execute(f'DROP DATABASE IF EXISTS "{name}"')
        admin.close()


def _seed_stale_job(dsn, *, owner, attempts, checkpoint):
    """Insert one expired running job and its completed parent scan."""
    scan_id, job_id = str(uuid.uuid4()), str(uuid.uuid4())
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scans
                    (scan_id, subscription_id, started_at, completed_at, status, cve_enrichment_status)
                VALUES (%s, %s, CURRENT_TIMESTAMP - INTERVAL '1 hour', CURRENT_TIMESTAMP,
                        'completed', 'ENRICHING')
                """,
                (scan_id, str(uuid.uuid4())),
            )
            cur.execute(
                """
                INSERT INTO enrichment_jobs
                    (job_id, scan_id, status, lease_owner, lease_expires_at, last_heartbeat_at,
                     fencing_token, attempt_count, next_retry_at, checkpoint, error_message)
                VALUES (%s, %s, 'running', %s,
                        CURRENT_TIMESTAMP - INTERVAL '5 minutes',
                        CURRENT_TIMESTAMP - INTERVAL '6 minutes',
                        17, %s, CURRENT_TIMESTAMP - INTERVAL '10 minutes', %s, %s)
                """,
                (job_id, scan_id, owner, attempts, checkpoint, f"previous error from {owner}"),
            )
    return scan_id, job_id


def _recovery_row(dsn, job_id):
    with psycopg2.connect(dsn) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT j.*, s.cve_enrichment_status
                FROM enrichment_jobs AS j
                JOIN scans AS s ON s.scan_id = j.scan_id
                WHERE j.job_id = %s
                """,
                (job_id,),
            )
            return dict(cur.fetchone())


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


def test_stale_recovery_skips_locked_job_and_recovers_it_on_the_next_pass():
    """A locked stale job is deferred without convoying other recovery work."""
    with _isolated_database() as dsn:
        _locked_scan, locked_job = _seed_stale_job(dsn, owner="locked-owner", attempts=1, checkpoint=11)
        _retry_scan, retry_job = _seed_stale_job(dsn, owner="retry-owner", attempts=1, checkpoint=22)
        _failed_scan, failed_job = _seed_stale_job(dsn, owner="failed-owner", attempts=3, checkpoint=33)

        locked_before = _recovery_row(dsn, locked_job)
        retry_before = _recovery_row(dsn, retry_job)
        failed_before = _recovery_row(dsn, failed_job)

        holder = psycopg2.connect(dsn)
        recovery_finished = threading.Event()
        result = {}

        def recover() -> None:
            db = DatabaseManager(dsn)
            started = time.perf_counter()
            try:
                result["count"] = db.recover_stale_enrichment_jobs(max_attempts=3)
            except Exception as exc:  # pragma: no cover - asserted in the caller
                result["error"] = exc
            finally:
                result["elapsed"] = time.perf_counter() - started
                db.close()
                recovery_finished.set()

        thread = threading.Thread(target=recover)
        lock_started = time.perf_counter()
        try:
            with holder.cursor() as cur:
                cur.execute("SELECT job_id FROM enrichment_jobs WHERE job_id = %s FOR UPDATE", (locked_job,))

            thread.start()
            # The lock is deliberately still held here. The timeout is only a
            # deadlock guard; the event proves recovery completed before this
            # transaction released Job A.
            assert recovery_finished.wait(timeout=2), "stale recovery blocked behind a locked enrichment job"
            assert "error" not in result
            assert result["count"] == 2

            locked_during = _recovery_row(dsn, locked_job)
            retry_after = _recovery_row(dsn, retry_job)
            failed_after = _recovery_row(dsn, failed_job)

            preserved_fields = (
                "status",
                "lease_owner",
                "lease_expires_at",
                "last_heartbeat_at",
                "fencing_token",
                "attempt_count",
                "next_retry_at",
                "checkpoint",
                "error_message",
                "completed_at",
                "cve_enrichment_status",
            )
            assert {field: locked_during[field] for field in preserved_fields} == {
                field: locked_before[field] for field in preserved_fields
            }

            assert retry_after["status"] == "pending"
            assert retry_after["lease_owner"] is None
            assert retry_after["lease_expires_at"] is None
            assert retry_after["attempt_count"] == retry_before["attempt_count"]
            assert retry_after["checkpoint"] == retry_before["checkpoint"]
            assert retry_after["fencing_token"] == retry_before["fencing_token"]
            assert retry_after["last_heartbeat_at"] == retry_before["last_heartbeat_at"]
            assert retry_after["next_retry_at"] == retry_before["next_retry_at"]
            assert retry_after["completed_at"] == retry_before["completed_at"]
            assert retry_after["error_message"] == "Enrichment worker interrupted; queued for retry."
            assert retry_after["cve_enrichment_status"] == "PENDING"

            assert failed_after["status"] == "failed"
            assert failed_after["lease_owner"] is None
            assert failed_after["lease_expires_at"] is None
            assert failed_after["attempt_count"] == failed_before["attempt_count"]
            assert failed_after["checkpoint"] == failed_before["checkpoint"]
            assert failed_after["fencing_token"] == failed_before["fencing_token"]
            assert failed_after["last_heartbeat_at"] == failed_before["last_heartbeat_at"]
            assert failed_after["next_retry_at"] == failed_before["next_retry_at"]
            assert failed_after["completed_at"] is not None
            assert failed_after["error_message"] == (
                "Enrichment exceeded maximum retry attempts after worker interruption."
            )
            assert failed_after["cve_enrichment_status"] == "FAILED"
        finally:
            result["lock_held"] = time.perf_counter() - lock_started
            holder.rollback()
            holder.close()
            if thread.ident is not None:
                thread.join(timeout=10)

        db = DatabaseManager(dsn)
        try:
            assert db.recover_stale_enrichment_jobs(max_attempts=3) == 1
        finally:
            db.close()

        locked_after = _recovery_row(dsn, locked_job)
        assert locked_after["status"] == "pending"
        assert locked_after["lease_owner"] is None
        assert locked_after["lease_expires_at"] is None
        assert locked_after["attempt_count"] == locked_before["attempt_count"]
        assert locked_after["checkpoint"] == locked_before["checkpoint"]
        assert locked_after["fencing_token"] == locked_before["fencing_token"]
        assert locked_after["cve_enrichment_status"] == "PENDING"
        assert result["elapsed"] < 2
        assert result["lock_held"] >= result["elapsed"]


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


def test_scan_enriched_before_durable_jobs_reports_completed_not_a_new_job(enrichment_scan):
    """A pre-durable-jobs enrichment must not be silently redone.

    Such a scan carries cve_enrichment_status COMPLETED but has no job row,
    so a plain insert would queue fresh work and answer "created". It has to
    resolve to the same completed outcome every other caller sees.
    """
    dsn, scan_id, _ = enrichment_scan
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            # Reproduce the legacy shape: enriched scan, no durable job row.
            cur.execute("DELETE FROM enrichment_jobs WHERE scan_id = %s", (scan_id,))
            cur.execute("UPDATE scans SET cve_enrichment_status = 'COMPLETED' WHERE scan_id = %s", (scan_id,))

    db = DatabaseManager(dsn)
    try:
        job, outcome = db.enqueue_enrichment_job(scan_id)
    finally:
        db.close()

    assert outcome == "completed"
    assert job["status"] == "completed"
    assert job["job_id"] is not None
    # The scan is not dragged back into the queue.
    row = _job_row(dsn, scan_id)
    assert row["status"] == "completed"
    assert _scan_enrichment_status(dsn, scan_id) == "COMPLETED"


def _scan_enrichment_status(dsn: str, scan_id: str) -> str:
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT cve_enrichment_status FROM scans WHERE scan_id = %s", (scan_id,))
            return cur.fetchone()[0]
