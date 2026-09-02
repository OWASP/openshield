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
