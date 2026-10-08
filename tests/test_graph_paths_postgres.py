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
                "(path_id,tenant_id,scan_id,source_node_id,target_node_id,path_node_ids,path_length,relationship_types) "
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
