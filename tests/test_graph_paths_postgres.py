"""Database regressions for current traversal and successful clean-scan retention."""

import os
import uuid
from dataclasses import replace

import psycopg2
import pytest

from scanner.graph.graph_populator import populate_graph
from scanner.graph.path_traversal import _delete_stale_paths, _load_adjacency, compute_attack_paths
from tests.test_graph_freshness_postgres import snapshot

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"), reason="requires PostgreSQL")


@pytest.fixture
def path_scope():
    tenant, sub = str(uuid.uuid4()), str(uuid.uuid4())
    dsn = os.environ["DATABASE_URL"]
    scans = []

    def scan(subscription=sub):
        sid = str(uuid.uuid4())
        scans.append(sid)
        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO scans (scan_id, subscription_id, started_at, status) VALUES (%s,%s,now(),'completed')",
                    (sid, subscription),
                )
        return sid

    yield tenant, sub, dsn, scan
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM attack_paths WHERE tenant_id=%s", (tenant,))
            cur.execute("DELETE FROM graph_nodes WHERE tenant_id=%s", (tenant,))
            cur.execute("DELETE FROM graph_snapshot_scopes WHERE tenant_id=%s", (tenant,))
            cur.execute("DELETE FROM findings WHERE scan_id=ANY(%s::uuid[])", (scans,))
            cur.execute("DELETE FROM scans WHERE scan_id=ANY(%s::uuid[])", (scans,))


def risky_scan(tenant, sub, dsn, sid):
    snap = snapshot(tenant, sub)
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO findings (scan_id, rule_id, rule_name, severity, resource_id, detected_at, finding_key) "
                "VALUES (%s,'AZ-TEST-001','test','HIGH',%s,now(),%s)",
                (sid, snap.resources[1].resource_id, uuid.uuid4().hex),
            )
    populate_graph(sid, snap, dsn)
    return snap


def path_count(dsn, tenant, sid):
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM attack_paths WHERE tenant_id=%s AND scan_id=%s", (tenant, sid))
            return cur.fetchone()[0]


def test_successful_clean_scan_clears_previous_paths_from_authoritative_scope(path_scope):
    tenant, sub, dsn, scan = path_scope
    risky = scan()
    risky_scan(tenant, sub, dsn, risky)
    # Seed one prior path so the cleanup regression is independent of traversal.
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT node_id::text FROM graph_nodes WHERE tenant_id=%s ORDER BY resource_id", (tenant,))
            nodes = [row[0] for row in cur.fetchall()]
            cur.execute(
                "INSERT INTO attack_paths "
                "(path_id,tenant_id,scan_id,source_node_id,target_node_id,"
                "path_node_ids,path_length,relationship_types) "
                "VALUES (%s,%s,%s,%s,%s,%s::uuid[],1,ARRAY['MEMBER_OF']) ON CONFLICT DO NOTHING",
                (str(uuid.uuid4()), tenant, risky, nodes[0], nodes[1], nodes),
            )
    clean = scan()
    assert path_count(dsn, tenant, risky) == 1
    with psycopg2.connect(dsn) as conn:
        _delete_stale_paths(conn, clean, tenant)
    assert path_count(dsn, tenant, risky) == 0


def test_partial_snapshot_does_not_traverse_retained_old_edge(path_scope):
    from scanner.arg_inventory import InventoryStatus

    tenant, sub, dsn, scan = path_scope
    first = scan()
    risky_scan(tenant, sub, dsn, first)
    with psycopg2.connect(dsn) as conn:
        assert _load_adjacency(conn, tenant)
    partial = snapshot(tenant, sub, status=InventoryStatus.PARTIAL, linked=False)
    populate_graph(scan(), replace(partial, resources=partial.resources[:1]), dsn)
    with psycopg2.connect(dsn) as conn:
        assert _load_adjacency(conn, tenant) == {}


def test_risky_then_clean_scan_computes_zero_and_removes_old_paths(path_scope):
    tenant, sub, dsn, scan = path_scope
    first = scan()
    risky_scan(tenant, sub, dsn, first)
    assert path_count(dsn, tenant, first) == 1
    clean = scan()
    populate_graph(clean, snapshot(tenant, sub, linked=False), dsn)
    assert compute_attack_paths(clean, tenant, dsn) == 0
    assert path_count(dsn, tenant, first) == 0


def test_clean_scan_retention_preserves_other_subscription_paths(path_scope):
    tenant, sub, dsn, scan = path_scope
    first = scan()
    risky_scan(tenant, sub, dsn, first)
    other_sub = str(uuid.uuid4())
    other = scan(other_sub)
    risky_scan(tenant, other_sub, dsn, other)
    clean = scan()
    assert compute_attack_paths(clean, tenant, dsn) == 0
    assert path_count(dsn, tenant, first) == 0
    assert path_count(dsn, tenant, other) == 1


def test_unsuccessful_scan_cannot_clear_previous_paths(path_scope):
    tenant, sub, dsn, scan = path_scope
    first = scan()
    risky_scan(tenant, sub, dsn, first)
    failed = scan()
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE scans SET status='failed' WHERE scan_id=%s", (failed,))
        _delete_stale_paths(conn, failed, tenant)
    assert path_count(dsn, tenant, first) == 1


def test_cleanup_keeps_other_tenants_paths(path_scope):
    tenant, sub, dsn, scan = path_scope
    other_tenant = str(uuid.uuid4())
    first, other = scan(), scan()
    try:
        risky_scan(tenant, sub, dsn, first)
        risky_scan(other_tenant, sub, dsn, other)
        clean = scan()
        compute_attack_paths(clean, tenant, dsn)
        assert path_count(dsn, tenant, first) == 0
        assert path_count(dsn, other_tenant, other) == 1
    finally:
        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM graph_nodes WHERE tenant_id=%s", (other_tenant,))
                cur.execute("DELETE FROM graph_snapshot_scopes WHERE tenant_id=%s", (other_tenant,))


def test_authenticated_graph_api_selects_only_current_verified_tenant_evidence(path_scope, client, app):
    import time
    import jwt
    from scanner.arg_inventory import InventoryStatus

    tenant, sub, dsn, scan = path_scope
    first = scan()
    risky_scan(tenant, sub, dsn, first)
    partial = snapshot(tenant, sub, status=InventoryStatus.PARTIAL, linked=False)
    populate_graph(scan(), replace(partial, resources=partial.resources[:1]), dsn)
    token = jwt.encode(
        {"sub": "graph-viewer", "role": "viewer", "tid": tenant, "exp": int(time.time()) + 60},
        app.config["JWT_SECRET"],
        algorithm="HS256",
    )
    foreign = str(uuid.uuid4())
    response = client.get(
        f"/api/attack-graph?subscription_id={sub}&tenant_id={foreign}",
        headers={"Authorization": f"Bearer {token}", "X-Tenant-Id": foreign},
    )
    assert response.status_code == 200
    result = response.get_json()
    assert len(result["nodes"]) == 1
    assert result["nodes"][0]["resource_id"] == partial.resources[0].resource_id.lower()
    assert result["edges"] == []


def test_delayed_older_traversal_cannot_delete_newer_paths(path_scope):
    tenant, sub, dsn, scan = path_scope
    older, newer = scan(), scan()
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE scans SET started_at=now()-interval '2 minutes' WHERE scan_id=%s", (older,))
            cur.execute("UPDATE scans SET started_at=now()-interval '1 minute' WHERE scan_id=%s", (newer,))
    risky_scan(tenant, sub, dsn, newer)
    assert path_count(dsn, tenant, newer) == 1
    assert compute_attack_paths(older, tenant, dsn) == 0
    assert path_count(dsn, tenant, newer) == 1


def test_traversal_waits_for_scope_publication_lock(path_scope):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    tenant, sub, dsn, scan = path_scope
    sid = scan()
    risky_scan(tenant, sub, dsn, sid)
    entered = Event()
    blocker = psycopg2.connect(dsn)
    try:
        with blocker.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"openshield-graph:{tenant}:{sub}",))

        def traverse():
            entered.set()
            return compute_attack_paths(sid, tenant, dsn)

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(traverse)
            assert entered.wait(2)
            try:
                future.result(timeout=0.3)
                pytest.fail("traversal completed while its scope lock was held")
            except TimeoutError:
                pass
            finally:
                blocker.rollback()
            assert future.result(timeout=5) == 0
        assert path_count(dsn, tenant, sid) == 1
    finally:
        blocker.close()
