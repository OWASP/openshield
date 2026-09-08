"""PostgreSQL coverage for durable operational metric aggregates."""

import os
import uuid

import psycopg2
import pytest

from api.models.finding import DatabaseManager


pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="DATABASE_URL is required for PostgreSQL tests"
)


def test_durable_operational_metrics_cover_queue_lease_retries_and_heartbeat():
    dsn = os.environ["DATABASE_URL"]
    scan_id, subscription_id = str(uuid.uuid4()), str(uuid.uuid4())
    db = DatabaseManager(dsn)
    try:
        db.create_pending_scan(scan_id, subscription_id)
        db.record_worker_heartbeat("worker-test", "scan")
        db.record_worker_heartbeat("worker-test", "enrichment")
        claim = db.claim_next_pending_scan("worker-a", 120, scan_id=scan_id)
        assert claim is not None
        snapshot = db.get_operational_metrics()
        assert snapshot["oldest_lease_age"]["scan"] >= 0
        # Aggregated over the whole table, so other rows in a shared test
        # database may contribute; only the shape is this test's contract.
        assert snapshot["retry_attempts"]["scan"] >= 0
        assert snapshot["worker_heartbeat_age"]["scan"] >= 0
        assert snapshot["worker_heartbeat_age"]["enrichment"] >= 0
        assert snapshot["last_successful_scan_timestamp"] >= 0
    finally:
        db.close()
        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM worker_heartbeats WHERE worker_id = 'worker-test'")
                cur.execute("DELETE FROM findings WHERE scan_id = %s", (scan_id,))
                cur.execute("DELETE FROM scans WHERE scan_id = %s", (scan_id,))


def test_stale_worker_heartbeats_are_pruned_without_dropping_live_workers():
    """Retired worker rows must not accumulate, and live ones must survive."""
    dsn = os.environ["DATABASE_URL"]
    live_worker, dead_worker = f"live-{uuid.uuid4()}", f"dead-{uuid.uuid4()}"
    db = DatabaseManager(dsn)
    try:
        db.record_worker_heartbeat(dead_worker, "scan")
        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE worker_heartbeats SET last_seen_at = CURRENT_TIMESTAMP - INTERVAL '30 days' "
                    "WHERE worker_id = %s",
                    (dead_worker,),
                )

        # Pruning happens on the beat that inserts a new worker identity.
        db.record_worker_heartbeat(live_worker, "scan", retention_seconds=7 * 24 * 60 * 60)

        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM worker_heartbeats WHERE worker_id = %s", (dead_worker,))
                assert cur.fetchone()[0] == 0
                cur.execute("SELECT COUNT(*) FROM worker_heartbeats WHERE worker_id = %s", (live_worker,))
                assert cur.fetchone()[0] == 1

        # A repeat beat from an existing worker only refreshes its timestamp.
        db.record_worker_heartbeat(live_worker, "scan")
        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM worker_heartbeats WHERE worker_id = %s", (live_worker,))
                assert cur.fetchone()[0] == 1
    finally:
        db.close()
        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM worker_heartbeats WHERE worker_id IN (%s, %s)",
                    (live_worker, dead_worker),
                )


def _oldest_other_running_lease_age(dsn: str, exclude_scan_id: str) -> float:
    """Age the metric would report from running scans other than this one.

    oldest_lease_age is a whole-table MIN, so a shared test database can carry
    unrelated running rows. Measuring them separately keeps the assertions
    below about this scan's lease rather than about the fixture ordering.
    """
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COALESCE(
                    EXTRACT(EPOCH FROM CURRENT_TIMESTAMP - MIN(COALESCE(last_heartbeat_at, claimed_at))), 0
                )
                FROM scans WHERE status = 'running' AND scan_id <> %s
                """,
                (exclude_scan_id,),
            )
            return float(cur.fetchone()[0])


def test_scan_lease_age_tracks_heartbeat_freshness_not_claim_time():
    """A healthy long scan must not look like a stalled one.

    The metric previously reported CURRENT_TIMESTAMP - MIN(claimed_at), which
    grows for the entire life of a scan even while its worker renews the lease
    on schedule. It must report the freshness of the current lease instead.
    """
    dsn = os.environ["DATABASE_URL"]
    scan_id, subscription_id = str(uuid.uuid4()), str(uuid.uuid4())
    db = DatabaseManager(dsn)
    try:
        db.create_pending_scan(scan_id, subscription_id)
        claim = db.claim_next_pending_scan("worker-a", 120, scan_id=scan_id)
        assert claim is not None

        # A scan claimed an hour ago whose worker has not checked in since.
        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scans
                    SET claimed_at = CURRENT_TIMESTAMP - INTERVAL '1 hour',
                        last_heartbeat_at = CURRENT_TIMESTAMP - INTERVAL '1 hour',
                        lease_expires_at = CURRENT_TIMESTAMP + INTERVAL '1 hour'
                    WHERE scan_id = %s
                    """,
                    (scan_id,),
                )

        # A genuinely stale lease reports its real age.
        assert db.get_operational_metrics()["oldest_lease_age"]["scan"] >= 3600

        # The worker checks in on time. claimed_at is deliberately left an
        # hour old: the lease is fresh even though the scan started long ago.
        db.heartbeat_scan(scan_id, "worker-a", claim["fencing_token"], 120)

        after = db.get_operational_metrics()["oldest_lease_age"]["scan"]
        others = _oldest_other_running_lease_age(dsn, scan_id)
        # This scan no longer contributes an hour of age; anything still
        # reported comes from unrelated running rows, not from this one.
        assert after < 3600 or after <= others + 5
        if others < 60:
            assert after < 60
    finally:
        db.close()
        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM enrichment_jobs WHERE scan_id = %s", (scan_id,))
                cur.execute("DELETE FROM rule_evaluations WHERE scan_id = %s", (scan_id,))
                cur.execute("DELETE FROM findings WHERE scan_id = %s", (scan_id,))
                cur.execute("DELETE FROM scans WHERE scan_id = %s", (scan_id,))
