"""End-to-end Postgres test for graph population using real ARG-shaped fixtures.

Verifies that populate_nodes and _write_edges write the expected rows to the
graph_nodes and graph_edges tables when given a VNet+NIC+VM+UAMI snapshot that
mirrors what Azure Resource Graph actually returns.

Requires DATABASE_URL and the graph schema migration to have been applied.
"""

import os
import uuid

import psycopg2
import pytest

from scanner.arg_inventory import InventoryResource, InventorySnapshot, InventoryStatus
from scanner.graph.edge_detector import detect_all_edges
from scanner.graph.graph_populator import _synthesise_subnet_resources, _write_edges
from scanner.graph.node_service import populate_nodes

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="DATABASE_URL is required for PostgreSQL graph tests",
)

_DSN = os.environ.get("DATABASE_URL", "")

# ---------------------------------------------------------------------------
# Unique tenant/sub per test run so parallel runs don't collide
# ---------------------------------------------------------------------------
_TENANT = f"test-tenant-{uuid.uuid4().hex[:8]}"
_SUB = f"test-sub-{uuid.uuid4().hex[:8]}"
_SNAP = f"snap-{uuid.uuid4().hex[:8]}"

_BASE = f"/subscriptions/{_SUB}/resourceGroups/rg-test/providers"
_VNET_ID = f"{_BASE}/Microsoft.Network/virtualNetworks/vnet-test"
_SUBNET_ID = f"{_VNET_ID}/subnets/default"
_NSG_ID = f"{_BASE}/Microsoft.Network/networkSecurityGroups/nsg-test"
_NIC_ID = f"{_BASE}/Microsoft.Network/networkInterfaces/nic-test"
_VM_ID = f"{_BASE}/Microsoft.Compute/virtualMachines/vm-test"
_IDENTITY_ID = f"{_BASE}/Microsoft.ManagedIdentity/userAssignedIdentities/id-test"
_PIP_ID = f"{_BASE}/Microsoft.Network/publicIPAddresses/pip-test"


def _resource(rid, rtype, properties=None):
    return InventoryResource(
        snapshot_id=_SNAP,
        tenant_id=_TENANT,
        subscription_id=_SUB,
        resource_id=rid,
        resource_type=rtype,
        name=rid.split("/")[-1],
        location="uksouth",
        resource_group="rg-test",
        tags={},
        properties=properties or {},
    )


# Real ARG response shapes for a VNet with one subnet, an NSG protecting it,
# a NIC in it, a VM with UAMI, and a public IP attached to the NIC.
_VNET = _resource(
    _VNET_ID,
    "microsoft.network/virtualnetworks",
    {
        "subnets": [
            {
                "id": _SUBNET_ID,
                "name": "default",
                "properties": {
                    "addressPrefix": "10.0.0.0/24",
                    "networkSecurityGroup": {"id": _NSG_ID},
                },
            }
        ],
        "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
    },
)

_NSG = _resource(
    _NSG_ID,
    "microsoft.network/networksecuritygroups",
    {"subnets": [{"id": _SUBNET_ID}]},
)

_NIC = _resource(
    _NIC_ID,
    "microsoft.network/networkinterfaces",
    {
        "ipConfigurations": [
            {
                "properties": {
                    "subnet": {"id": _SUBNET_ID},
                    "privateIPAddress": "10.0.0.4",
                    "publicIPAddress": {"id": _PIP_ID},
                }
            }
        ],
        "virtualMachine": {"id": _VM_ID},
    },
)

_VM = _resource(
    _VM_ID,
    "microsoft.compute/virtualmachines",
    {
        "identity": {
            "type": "UserAssigned",
            "userAssignedIdentities": {_IDENTITY_ID: {}},
        },
        "networkProfile": {"networkInterfaces": [{"id": _NIC_ID}]},
    },
)

_PIP = _resource(
    _PIP_ID,
    "microsoft.network/publicipaddresses",
    {"ipConfiguration": {"id": f"{_NIC_ID}/ipConfigurations/ipconfig1"}},
)

_IDENTITY = _resource(
    _IDENTITY_ID,
    "microsoft.managedidentity/userassignedidentities",
    {},
)


def _snapshot(*resources):
    return InventorySnapshot(
        snapshot_id=_SNAP,
        tenant_id=_TENANT,
        requested_subscriptions=(_SUB,),
        status=InventoryStatus.COMPLETE,
        collected_at="2026-09-30T00:00:00+00:00",
        duration_ms=42,
        pages=1,
        resources=tuple(resources),
        errors=(),
    )


@pytest.fixture(scope="module")
def db_conn():
    conn = psycopg2.connect(_DSN)
    yield conn
    # Clean up all rows written by this test run
    with conn.cursor() as cur:
        cur.execute("DELETE FROM graph_edges WHERE evidence_snapshot_id = %s", (_SNAP,))
        cur.execute("DELETE FROM graph_nodes WHERE tenant_id = %s", (_TENANT,))
    conn.commit()
    conn.close()


@pytest.fixture(scope="module")
def populated_graph(db_conn):
    """Run populate_nodes + detect_all_edges + _write_edges once; return edge list."""
    base_snapshot = _snapshot(_VNET, _NSG, _NIC, _VM, _PIP, _IDENTITY)
    subnet_resources = _synthesise_subnet_resources(base_snapshot)
    from dataclasses import replace as dc_replace

    augmented = dc_replace(base_snapshot, resources=base_snapshot.resources + tuple(subnet_resources))

    populate_nodes(augmented, _DSN)
    edges = detect_all_edges(augmented)
    _write_edges(edges, _SNAP, _TENANT, _DSN)
    return edges


def test_vnet_node_written_to_db(db_conn, populated_graph):
    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT resource_type FROM graph_nodes WHERE tenant_id = %s AND lower(resource_id) = lower(%s)",
            (_TENANT, _VNET_ID),
        )
        row = cur.fetchone()
    assert row is not None, "VNet node must be written to graph_nodes"
    assert "virtualnetwork" in row[0].lower()


def test_subnet_node_synthesised_and_written(db_conn, populated_graph):
    """Subnet is nested in VNet properties — must be synthesised and written as a node."""
    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT resource_type FROM graph_nodes WHERE tenant_id = %s AND lower(resource_id) = lower(%s)",
            (_TENANT, _SUBNET_ID),
        )
        row = cur.fetchone()
    assert row is not None, "Synthesised subnet node must be written to graph_nodes"
    assert "subnet" in row[0].lower()


def test_nsg_to_subnet_protects_edge_written(db_conn, populated_graph):
    """NSG -> subnet PROTECTS edge must be written to graph_edges."""
    with db_conn.cursor() as cur:
        cur.execute(
            """
            SELECT ge.relationship_type
            FROM graph_edges ge
            JOIN graph_nodes src ON src.node_id = ge.source_node_id
            JOIN graph_nodes tgt ON tgt.node_id = ge.target_node_id
            WHERE lower(src.resource_id) = lower(%s)
              AND lower(tgt.resource_id) = lower(%s)
              AND ge.evidence_snapshot_id = %s
            """,
            (_NSG_ID, _SUBNET_ID, _SNAP),
        )
        row = cur.fetchone()
    assert row is not None, "PROTECTS edge from NSG to subnet must be in graph_edges"
    assert row[0] == "PROTECTS"


def test_nic_to_subnet_member_of_edge_written(db_conn, populated_graph):
    """NIC -> subnet MEMBER_OF edge must be written (NIC subnet path: ipConfigurations[].properties.subnet.id)."""
    with db_conn.cursor() as cur:
        cur.execute(
            """
            SELECT ge.relationship_type
            FROM graph_edges ge
            JOIN graph_nodes src ON src.node_id = ge.source_node_id
            JOIN graph_nodes tgt ON tgt.node_id = ge.target_node_id
            WHERE lower(src.resource_id) = lower(%s)
              AND lower(tgt.resource_id) = lower(%s)
              AND ge.evidence_snapshot_id = %s
            """,
            (_NIC_ID, _SUBNET_ID, _SNAP),
        )
        row = cur.fetchone()
    assert row is not None, "MEMBER_OF edge from NIC to subnet must be in graph_edges"
    assert row[0] == "MEMBER_OF"


def test_vm_to_identity_has_identity_edge_written(db_conn, populated_graph):
    """VM -> UAMI HAS_IDENTITY edge must be written (identity field from bag_merge in ARG query)."""
    with db_conn.cursor() as cur:
        cur.execute(
            """
            SELECT ge.relationship_type
            FROM graph_edges ge
            JOIN graph_nodes src ON src.node_id = ge.source_node_id
            JOIN graph_nodes tgt ON tgt.node_id = ge.target_node_id
            WHERE lower(src.resource_id) = lower(%s)
              AND lower(tgt.resource_id) = lower(%s)
              AND ge.evidence_snapshot_id = %s
            """,
            (_VM_ID, _IDENTITY_ID, _SNAP),
        )
        row = cur.fetchone()
    assert row is not None, "HAS_IDENTITY edge from VM to UAMI must be in graph_edges"
    assert row[0] == "HAS_IDENTITY"


def test_cross_tenant_edges_not_written(db_conn, populated_graph):
    """Edges must be scoped to tenant — no edges should appear under a different tenant."""
    with db_conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*)
            FROM graph_edges ge
            JOIN graph_nodes src ON src.node_id = ge.source_node_id
            WHERE src.tenant_id = 'other-tenant'
              AND ge.evidence_snapshot_id = %s
            """,
            (_SNAP,),
        )
        count = cur.fetchone()[0]
    assert count == 0, "No edges must be written for a different tenant"


def test_no_edges_written_for_empty_snapshot(db_conn):
    """An empty snapshot must produce zero node and edge rows."""
    empty_snap_id = f"snap-empty-{uuid.uuid4().hex[:8]}"
    empty_tenant = f"tenant-empty-{uuid.uuid4().hex[:8]}"
    empty_snapshot = InventorySnapshot(
        snapshot_id=empty_snap_id,
        tenant_id=empty_tenant,
        requested_subscriptions=(_SUB,),
        status=InventoryStatus.COMPLETE,
        collected_at="2026-09-30T00:00:00+00:00",
        duration_ms=1,
        pages=0,
        resources=(),
        errors=(),
    )
    node_count = populate_nodes(empty_snapshot, _DSN)
    edges = detect_all_edges(empty_snapshot)
    edge_count = _write_edges(edges, empty_snap_id, empty_tenant, _DSN)
    assert node_count == 0
    assert edge_count == 0
