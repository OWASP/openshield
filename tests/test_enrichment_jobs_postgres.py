"""PostgreSQL lease, retry, and resume tests for durable enrichment jobs."""

import os
import threading
import uuid
from unittest.mock import patch

import psycopg2
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
        claim = db.claim_next_pending_scan("seed", 120)
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
        job, created = db.enqueue_enrichment_job(scan_id)
        assert created is False
        yield dsn, scan_id, job
    finally:
        db.close()
        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM enrichment_jobs WHERE scan_id = %s", (scan_id,))
                cur.execute("DELETE FROM rule_evaluations WHERE scan_id = %s", (scan_id,))
                cur.execute("DELETE FROM findings WHERE scan_id = %s", (scan_id,))
                cur.execute("DELETE FROM scans WHERE scan_id = %s", (scan_id,))


def _claim(dsn):
    db = DatabaseManager(dsn)
    try:
        return db.claim_next_enrichment_job("worker-a", 120)
    finally:
        db.close()


def test_duplicate_enqueue_and_claim_race(enrichment_scan):
    dsn, scan_id, first_job = enrichment_scan
    db = DatabaseManager(dsn)
    try:
        replay, created = db.enqueue_enrichment_job(scan_id)
    finally:
        db.close()
    assert created is False
    assert replay["job_id"] == first_job["job_id"]

    barrier = threading.Barrier(2)
    claims = []

    def claim():
        barrier.wait()
        claims.append(_claim(dsn))

    threads = [threading.Thread(target=claim) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len([job for job in claims if job]) == 1


def test_checkpoint_resume_and_completion(enrichment_scan):
    dsn, scan_id, _ = enrichment_scan
    job = _claim(dsn)
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
        resumed = db.claim_next_enrichment_job("worker-b", 120)
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
            job = db.claim_next_enrichment_job("worker-a", 120)
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
    first = _claim(dsn)
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
        assert db.recover_stale_enrichment_jobs() == 1
        second = db.claim_next_enrichment_job("worker-b", 120)
        assert second["fencing_token"] > first["fencing_token"]
        with pytest.raises(LostLease):
            db.heartbeat_enrichment_job(str(first["job_id"]), "worker-a", first["fencing_token"], 120)
    finally:
        db.close()
