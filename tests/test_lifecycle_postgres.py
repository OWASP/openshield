"""Lifecycle transitions against a migrated PostgreSQL database."""

import os
import uuid

import pytest

from api.services.lifecycle_service import LifecycleService

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"), reason="requires migrated PostgreSQL")


def test_resolution_requires_current_pass_for_each_resource():
    import psycopg2

    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    tenant = f"lifecycle-test-{uuid.uuid4()}"
    subscription = str(uuid.uuid4())
    scans = [str(uuid.uuid4()) for _ in range(5)]
    service = LifecycleService()
    outcome = [{"rule_id": "AZ-TEST-001", "status": "SUCCESS"}]
    resources = ["/resource/pass", "/resource/unknown", "/resource/unobserved"]
    findings = [{"rule_id": "AZ-TEST-001", "resource_id": resource} for resource in resources]

    def states():
        with conn.cursor() as cur:
            cur.execute(
                "SELECT ff.resource_id_normalized, fl.state FROM finding_lifecycles fl "
                "JOIN finding_fingerprints ff ON ff.id = fl.fingerprint_id WHERE ff.tenant_id = %s",
                (tenant,),
            )
            return dict(cur.fetchall())

    try:
        with conn.cursor() as cur:
            for scan in scans:
                cur.execute(
                    "INSERT INTO scans (scan_id, subscription_id, started_at, status) "
                    "VALUES (%s, %s, NOW(), 'completed')",
                    (scan, subscription),
                )
        conn.commit()
        service.apply_scan(conn, scans[0], subscription, tenant, outcome, findings)
        assert set(states().values()) == {"OPEN"}
        evidence = [
            {"rule_id": "AZ-TEST-001", "resource_id": resources[0], "status": "PASS"},
            {"rule_id": "AZ-TEST-001", "resource_id": resources[1], "status": "UNKNOWN"},
        ]
        service.apply_scan(conn, scans[1], subscription, tenant, outcome, [], evaluations=evidence)
        assert states() == {resources[0]: "RESOLVED", resources[1]: "OPEN", resources[2]: "OPEN"}
        service.apply_scan(conn, scans[2], subscription, tenant, outcome, findings[:1])
        assert states()[resources[0]] == "REOPENED"
        service.apply_scan(
            conn,
            scans[3],
            subscription,
            tenant,
            [{"rule_id": "AZ-TEST-001", "status": "FAILED"}],
            [],
            evaluations=evidence,
        )
        assert states()[resources[0]] == "REOPENED"
        service.apply_scan(conn, scans[4], subscription, tenant, outcome, [], evaluations=evidence)
        assert states()[resources[0]] == "RESOLVED"
        service.apply_scan(conn, scans[4], subscription, tenant, outcome, [], evaluations=evidence)
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM finding_lifecycle_transitions WHERE scan_id = %s", (scans[4],))
            assert cur.fetchone()[0] == 1
    finally:
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM finding_lifecycle_transitions WHERE lifecycle_id IN "
                "(SELECT fl.id FROM finding_lifecycles fl JOIN finding_fingerprints ff "
                "ON ff.id = fl.fingerprint_id WHERE ff.tenant_id = %s)",
                (tenant,),
            )
            cur.execute(
                "DELETE FROM finding_lifecycles WHERE fingerprint_id IN "
                "(SELECT id FROM finding_fingerprints WHERE tenant_id = %s)",
                (tenant,),
            )
            cur.execute("DELETE FROM finding_fingerprints WHERE tenant_id = %s", (tenant,))
            cur.execute("DELETE FROM scan_rule_outcomes WHERE scan_id = ANY(%s::uuid[])", (scans,))
            cur.execute("DELETE FROM scan_lifecycle_applications WHERE scan_id = ANY(%s::uuid[])", (scans,))
            cur.execute("DELETE FROM scans WHERE scan_id = ANY(%s::uuid[])", (scans,))
        conn.commit()
        conn.close()
