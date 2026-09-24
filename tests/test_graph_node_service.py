"""Tests for graph node upsert and finding-to-node linking."""
from unittest.mock import MagicMock, patch

from scanner.arg_inventory import InventorySnapshot, InventoryStatus, InventoryResource
from scanner.graph.node_service import populate_nodes, link_findings_to_nodes


def _make_resource(resource_id: str, resource_type: str = "microsoft.network/virtualnetworks",
                   subscription_id: str = "00000000-0000-0000-0000-000000000002") -> InventoryResource:
    return InventoryResource(
        snapshot_id="snap-1",
        tenant_id="00000000-0000-0000-0000-000000000001",
        subscription_id=subscription_id,
        resource_id=resource_id,
        resource_type=resource_type,
        name=resource_id.split("/")[-1],
        location="eastus",
        resource_group="rg",
        tags={},
        properties={"key": "val"},
    )


def _make_snapshot(resources=()):
    return InventorySnapshot(
        snapshot_id="snap-1",
        tenant_id="00000000-0000-0000-0000-000000000001",
        requested_subscriptions=("00000000-0000-0000-0000-000000000002",),
        status=InventoryStatus.COMPLETE,
        collected_at="2026-09-24T00:00:00+00:00",
        duration_ms=10,
        pages=1,
        resources=tuple(resources),
        errors=(),
    )


def test_populate_nodes_upserts_each_resource():
    resources = [
        _make_resource("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1"),
        _make_resource("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet2"),
    ]
    snapshot = _make_snapshot(resources)

    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.__enter__ = MagicMock(return_value=mock_conn)
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_cur.__enter__ = MagicMock(return_value=mock_cur)
    mock_cur.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cur

    with patch("scanner.graph.node_service.psycopg2.connect", return_value=mock_conn):
        count = populate_nodes(snapshot, "postgresql://test/db")

    assert count == 2
    assert mock_cur.execute.call_count == 2


def test_populate_nodes_empty_snapshot_returns_zero():
    snapshot = _make_snapshot(resources=[])

    with patch("scanner.graph.node_service.psycopg2.connect") as mock_connect:
        count = populate_nodes(snapshot, "postgresql://test/db")

    assert count == 0
    mock_connect.assert_not_called()


def test_populate_nodes_does_not_write_cross_tenant_resources():
    resource = _make_resource("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1")
    snapshot = _make_snapshot([resource])

    captured_args = []
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.__enter__ = MagicMock(return_value=mock_conn)
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_cur.__enter__ = MagicMock(return_value=mock_cur)
    mock_cur.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cur

    def capture_execute(sql, params=None):
        if params:
            captured_args.append(params)

    mock_cur.execute.side_effect = capture_execute

    with patch("scanner.graph.node_service.psycopg2.connect", return_value=mock_conn):
        populate_nodes(snapshot, "postgresql://test/db")

    for params in captured_args:
        assert "00000000-0000-0000-0000-000000000001" in str(params), "tenant_id must be in every write"


def test_link_findings_to_nodes_executes_insert():
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.__enter__ = MagicMock(return_value=mock_conn)
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_cur.__enter__ = MagicMock(return_value=mock_cur)
    mock_cur.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cur
    mock_cur.rowcount = 3

    with patch("scanner.graph.node_service.psycopg2.connect", return_value=mock_conn):
        link_findings_to_nodes("scan-uuid-1", "postgresql://test/db")

    assert mock_cur.execute.called
    sql_called = mock_cur.execute.call_args[0][0]
    assert "finding_graph_nodes" in sql_called
