"""Real PostgreSQL tests for durable scan admission invariants."""

import os
import threading
import uuid

import psycopg2
import pytest

from api.models.finding import DatabaseManager, ScanQuotaExceeded


pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="DATABASE_URL is required for PostgreSQL tests"
)


@pytest.fixture
def admitted_scans():
    dsn = os.environ["DATABASE_URL"]
    scan_ids: list[str] = []
    yield dsn, scan_ids
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            for scan_id in scan_ids:
                cur.execute("DELETE FROM findings WHERE scan_id = %s", (scan_id,))
                cur.execute("DELETE FROM scans WHERE scan_id = %s", (scan_id,))


def _admit(dsn: str, subscription_id: str, key: str | None = None):
    db = DatabaseManager(dsn)
    try:
        return db.admit_scan(str(uuid.uuid4()), subscription_id, idempotency_key=key)
    finally:
        db.close()


def test_concurrent_admission_returns_one_active_scan(admitted_scans):
    dsn, scan_ids = admitted_scans
    subscription_id = str(uuid.uuid4())
    barrier = threading.Barrier(2)
    outcomes = []

    def admit() -> None:
        barrier.wait()
        outcomes.append(_admit(dsn, subscription_id))

    threads = [threading.Thread(target=admit) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    scan_ids.append(str(outcomes[0][0]["scan_id"]))
    assert {str(scan["scan_id"]) for scan, _created in outcomes} == {scan_ids[0]}
    assert sum(created for _scan, created in outcomes) == 1


def test_idempotency_key_replays_the_same_logical_scan(admitted_scans):
    dsn, scan_ids = admitted_scans
    subscription_id = str(uuid.uuid4())
    key = f"request-{uuid.uuid4()}"
    first, created = _admit(dsn, subscription_id, key)
    scan_ids.append(str(first["scan_id"]))
    replay, replay_created = _admit(dsn, subscription_id, key)

    assert created is True
    assert replay_created is False
    assert replay["scan_id"] == first["scan_id"]


def test_idempotency_key_is_scoped_to_its_subscription(admitted_scans):
    """The documented scope: one key means different things per subscription.

    A trigger's only semantic input is subscription_id, so within a
    subscription a key hit is always a replay. Reusing the key under another
    subscription is a genuinely different request and admits its own scan
    rather than replaying or conflicting.
    """
    dsn, scan_ids = admitted_scans
    key = f"shared-{uuid.uuid4()}"
    first, first_created = _admit(dsn, str(uuid.uuid4()), key)
    scan_ids.append(str(first["scan_id"]))
    second, second_created = _admit(dsn, str(uuid.uuid4()), key)
    scan_ids.append(str(second["scan_id"]))

    assert first_created is True
    assert second_created is True
    assert first["scan_id"] != second["scan_id"]


def test_completed_scan_allows_a_later_admission_and_configured_quota(admitted_scans):
    dsn, scan_ids = admitted_scans
    subscription_id = str(uuid.uuid4())
    first, _ = _admit(dsn, subscription_id)
    scan_ids.append(str(first["scan_id"]))
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE scans SET status = 'completed' WHERE scan_id = %s", (first["scan_id"],))

    second, created = _admit(dsn, subscription_id)
    scan_ids.append(str(second["scan_id"]))
    assert created is True
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE scans SET status = 'completed' WHERE scan_id = %s", (second["scan_id"],))

    db = DatabaseManager(dsn)
    try:
        with pytest.raises(ScanQuotaExceeded):
            db.admit_scan(str(uuid.uuid4()), subscription_id, max_scans_per_hour=2)
    finally:
        db.close()
