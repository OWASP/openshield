"""Real database coverage for durable lifecycle admission, fencing and rollback."""

import os
import uuid

import psycopg2
import pytest

from api.models.finding import DatabaseManager
from scanner.lifecycle_worker import process_lifecycle_job
from tests.test_enrichment_jobs_postgres import _isolated_database

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"), reason="requires PostgreSQL")


@pytest.fixture
def lifecycle_job(monkeypatch):
    with _isolated_database() as dsn:
        tenant = str(uuid.uuid4())
        monkeypatch.setenv("AZURE_TENANT_ID", tenant.upper())
        monkeypatch.delenv("OPENSHIELD_TENANT_ID", raising=False)
        db = DatabaseManager(dsn)
        scan_id, subscription = str(uuid.uuid4()), str(uuid.uuid4())
        db.create_pending_scan(scan_id, subscription)
        claim = db.claim_next_pending_scan("scan-worker", 120, scan_id=scan_id)
        db.save_scan(
            {
                "scan_id": scan_id,
                "subscription_id": subscription,
                "findings": [
                    {
                        "rule_id": "AZ-TEST-001",
                        "rule_name": "Test",
                        "resource_id": "/resource/a",
                        "severity": "HIGH",
                        "detected_at": "2026-10-23T00:00:00Z",
                    }
                ],
                "evaluations": [],
            },
            "scan-worker",
            claim["fencing_token"],
        )
        job = db.claim_next_lifecycle_job("lifecycle-worker", 120)
        assert str(job["scan_id"]) == scan_id
        try:
            yield db, dsn, job, tenant
        finally:
            db.close()


def _state(dsn, scan_id):
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM scan_lifecycle_applications WHERE scan_id=%s", (scan_id,))
        applications = cur.fetchone()[0]
        cur.execute("SELECT status FROM lifecycle_jobs WHERE scan_id=%s", (scan_id,))
        return applications, cur.fetchone()[0]


def test_saved_scan_is_applied_and_job_completed_together(lifecycle_job):
    db, dsn, job, tenant = lifecycle_job
    assert process_lifecycle_job(db, job, "lifecycle-worker", 120) == "completed"
    assert _state(dsn, str(job["scan_id"])) == (1, "completed")
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT state FROM finding_lifecycles fl JOIN finding_fingerprints ff "
            "ON ff.id=fl.fingerprint_id WHERE ff.tenant_id=%s",
            (tenant,),
        )
        assert cur.fetchall() == [("OPEN",)]


def test_pattern_failure_rolls_back_lifecycle_and_retries(lifecycle_job, monkeypatch):
    db, dsn, job, _ = lifecycle_job

    def fail(*args, **kwargs):
        raise RuntimeError("simulated detector interruption")

    monkeypatch.setattr("scanner.lifecycle_worker.PatternService.detect_and_publish", fail)
    assert process_lifecycle_job(db, job, "lifecycle-worker", 120) == "retry"
    assert _state(dsn, str(job["scan_id"])) == (0, "pending")


def test_expired_worker_cannot_apply_lifecycle(lifecycle_job):
    db, dsn, job, _ = lifecycle_job
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE lifecycle_jobs SET lease_expires_at=NOW()-INTERVAL '1 second' WHERE job_id=%s",
            (str(job["job_id"]),),
        )
    assert process_lifecycle_job(db, job, "lifecycle-worker", 120) == "lost_lease"
    assert _state(dsn, str(job["scan_id"])) == (0, "running")
    assert db.recover_stale_lifecycle_jobs() == 1
    next_job = db.claim_next_lifecycle_job("replacement-worker", 120)
    assert next_job["fencing_token"] > job["fencing_token"]
    assert process_lifecycle_job(db, job, "lifecycle-worker", 120) == "lost_lease"
    assert process_lifecycle_job(db, next_job, "replacement-worker", 120) == "completed"


def test_lifecycle_applies_findings_beyond_public_page_limit(lifecycle_job):
    from psycopg2.extras import execute_values

    db, dsn, job, tenant = lifecycle_job
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        execute_values(
            cur,
            "INSERT INTO findings(scan_id,rule_id,rule_name,resource_id,severity,detected_at,finding_key) VALUES %s",
            [
                (str(job["scan_id"]), "AZ-TEST-001", "Test", f"/resource/{i}", "HIGH", "2026-10-23", str(uuid.uuid4()))
                for i in range(1000)
            ],
        )
    assert process_lifecycle_job(db, job, "lifecycle-worker", 120) == "completed"
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM finding_fingerprints WHERE tenant_id=%s", (tenant,))
        assert cur.fetchone()[0] == 1001


def test_same_resource_evidence_variants_are_not_cross_resource_patterns(lifecycle_job):
    from api.services.lifecycle_service import LifecycleService
    from api.services.pattern_service import PatternService

    db, dsn, job, tenant = lifecycle_job
    scan = db.get_scan(str(job["scan_id"]))
    LifecycleService().apply_scan(
        db._get_conn(),
        str(job["scan_id"]),
        scan["subscription_id"],
        tenant,
        [],
        [{"rule_id": "AZ-TEST-001", "resource_id": "/resource/a", "evidence_key": key} for key in ("one", "two")],
    )
    assert (
        PatternService().detect_and_publish(db._get_conn(), str(job["scan_id"]), scan["subscription_id"], tenant) == 0
    )


def test_delayed_scan_does_not_publish_newer_state_under_old_scan_id(lifecycle_job):
    from api.services.lifecycle_service import LifecycleService
    from api.services.pattern_service import PatternService

    db, dsn, job, tenant = lifecycle_job
    scan = db.get_scan(str(job["scan_id"]))
    newer = str(uuid.uuid4())
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO scans(scan_id,subscription_id,started_at,status) "
            "VALUES(%s,%s,NOW()+INTERVAL '5 seconds','completed')",
            (newer, scan["subscription_id"]),
        )
    LifecycleService().apply_scan(
        db._get_conn(),
        newer,
        scan["subscription_id"],
        tenant,
        [],
        [{"rule_id": "AZ-TEST-001", "resource_id": "/resource/a"}],
    )
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("UPDATE finding_lifecycles SET occurrence_count=3")
    PatternService().detect_and_publish(db._get_conn(), newer, scan["subscription_id"], tenant)
    assert process_lifecycle_job(db, job, "lifecycle-worker", 120) == "completed"
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT scan_id::text FROM patterns")
        assert cur.fetchall() == [(newer,)]
