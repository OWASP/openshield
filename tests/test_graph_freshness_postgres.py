"""Current graph evidence across successive complete and partial scans."""

import os
import uuid
from dataclasses import replace

import psycopg2
import pytest

from scanner.arg_inventory import InventoryResource, InventorySnapshot, InventoryStatus
from scanner.graph.graph_populator import populate_graph

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"), reason="requires PostgreSQL")


@pytest.fixture
def graph_scope():
    tenant, subscription = str(uuid.uuid4()), str(uuid.uuid4())
    dsn = os.environ["DATABASE_URL"]
    yield tenant, subscription, dsn
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM graph_nodes WHERE tenant_id = %s", (tenant,))
            cur.execute("DELETE FROM graph_snapshot_scopes WHERE tenant_id = %s", (tenant,))


def snapshot(tenant, subscription, *, status=InventoryStatus.COMPLETE, linked=True, empty=False):
    sid = str(uuid.uuid4())
    prefix = f"/subscriptions/{subscription}/resourceGroups/rg/providers/Microsoft.Network/"
    subnet = prefix + "virtualNetworks/v/subnets/s"
    nic = prefix + "networkInterfaces/n"

    def resource(rid, kind, properties):
        return InventoryResource(
            sid, tenant, subscription, rid, kind, rid.split("/")[-1], "uksouth", "rg", {}, properties
        )

    resources = (
        ()
        if empty
        else (
            resource(subnet, "microsoft.network/virtualnetworks/subnets", {}),
            resource(
                nic,
                "microsoft.network/networkinterfaces",
                {"ipConfigurations": [{"properties": {"subnet": {"id": subnet}}}]} if linked else {},
            ),
        )
    )
    return InventorySnapshot(sid, tenant, (subscription,), status, "2026-10-07T00:00:00Z", 1, 1, resources, ())


def counts(dsn, tenant, subscription, current=False):
    table = "current_graph_nodes" if current else "graph_nodes"
    edges = "current_graph_edges" if current else "graph_edges"
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT count(*) FROM {table} WHERE tenant_id=%s AND subscription_id=%s", (tenant, subscription)
            )
            nodes = cur.fetchone()[0]
            cur.execute(
                f"SELECT count(*) FROM {edges} e JOIN graph_nodes n ON n.node_id=e.source_node_id "
                "WHERE n.tenant_id=%s AND n.subscription_id=%s",
                (tenant, subscription),
            )
            return nodes, cur.fetchone()[0]


def test_complete_snapshot_removes_detached_relationship(graph_scope):
    tenant, sub, dsn = graph_scope
    populate_graph(str(uuid.uuid4()), snapshot(tenant, sub), dsn)
    assert counts(dsn, tenant, sub) == (2, 1)
    populate_graph(str(uuid.uuid4()), snapshot(tenant, sub, linked=False), dsn)
    assert counts(dsn, tenant, sub) == (2, 0)
    assert counts(dsn, tenant, sub, current=True) == (2, 0)


def test_empty_complete_snapshot_expires_only_its_scope(graph_scope):
    tenant, sub, dsn = graph_scope
    other = str(uuid.uuid4())
    populate_graph(str(uuid.uuid4()), snapshot(tenant, sub), dsn)
    populate_graph(str(uuid.uuid4()), snapshot(tenant, other), dsn)
    populate_graph(str(uuid.uuid4()), snapshot(tenant, sub, empty=True), dsn)
    assert counts(dsn, tenant, sub) == (0, 0)
    assert counts(dsn, tenant, other, current=True) == (2, 1)


def test_partial_snapshot_preserves_history_but_hides_unobserved_evidence(graph_scope):
    tenant, sub, dsn = graph_scope
    populate_graph(str(uuid.uuid4()), snapshot(tenant, sub), dsn)
    partial = snapshot(tenant, sub, status=InventoryStatus.PARTIAL, linked=False)
    partial = replace(partial, resources=partial.resources[:1])
    populate_graph(str(uuid.uuid4()), partial, dsn)
    assert counts(dsn, tenant, sub) == (2, 1)
    assert counts(dsn, tenant, sub, current=True) == (1, 0)


def test_failed_snapshot_keeps_last_published_scope(graph_scope):
    tenant, sub, dsn = graph_scope
    populate_graph(str(uuid.uuid4()), snapshot(tenant, sub), dsn)
    populate_graph(str(uuid.uuid4()), snapshot(tenant, sub, status=InventoryStatus.FAILED, empty=True), dsn)
    assert counts(dsn, tenant, sub, current=True) == (2, 1)


def test_foreign_resource_cannot_overwrite_other_tenant(graph_scope):
    tenant, sub, dsn = graph_scope
    good = snapshot(tenant, sub)
    populate_graph(str(uuid.uuid4()), good, dsn)
    foreign = replace(good, tenant_id=str(uuid.uuid4()), snapshot_id=str(uuid.uuid4()))
    populate_graph(str(uuid.uuid4()), foreign, dsn)
    assert counts(dsn, tenant, sub, current=True) == (2, 1)


def test_publication_failure_keeps_previous_graph_atomically(graph_scope, monkeypatch):
    tenant, sub, dsn = graph_scope
    populate_graph(str(uuid.uuid4()), snapshot(tenant, sub), dsn)

    def fail_edges(_snapshot):
        raise RuntimeError("detector failure")

    monkeypatch.setattr("scanner.graph.graph_populator.detect_all_edges", fail_edges)
    populate_graph(str(uuid.uuid4()), snapshot(tenant, sub, linked=False), dsn)
    assert counts(dsn, tenant, sub, current=True) == (2, 1)


def test_complete_snapshot_does_not_prune_another_tenant(graph_scope):
    tenant, sub, dsn = graph_scope
    other = str(uuid.uuid4())
    try:
        populate_graph(str(uuid.uuid4()), snapshot(tenant, sub), dsn)
        populate_graph(str(uuid.uuid4()), snapshot(other, sub), dsn)
        populate_graph(str(uuid.uuid4()), snapshot(tenant, sub, empty=True), dsn)
        assert counts(dsn, other, sub, current=True) == (2, 1)
    finally:
        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM graph_nodes WHERE tenant_id=%s", (other,))
                cur.execute("DELETE FROM graph_snapshot_scopes WHERE tenant_id=%s", (other,))
