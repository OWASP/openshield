"""Tests for the snapshot bridge that wraps ArgInventoryClient for use in ScanEngine."""
from unittest.mock import MagicMock, patch

from scanner.arg_inventory import InventorySnapshot, InventoryStatus, InventoryResource
from scanner.graph.snapshot_bridge import collect_snapshot


def _make_snapshot(status=InventoryStatus.COMPLETE, errors=()):
    resource = InventoryResource(
        snapshot_id="snap-1",
        tenant_id="00000000-0000-0000-0000-000000000001",
        subscription_id="00000000-0000-0000-0000-000000000002",
        resource_id="/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1",
        resource_type="microsoft.network/virtualnetworks",
        name="vnet1",
        location="eastus",
        resource_group="rg",
        tags={},
        properties={},
    )
    return InventorySnapshot(
        snapshot_id="snap-1",
        tenant_id="00000000-0000-0000-0000-000000000001",
        requested_subscriptions=("00000000-0000-0000-0000-000000000002",),
        status=status,
        collected_at="2026-09-24T00:00:00+00:00",
        duration_ms=100,
        pages=1,
        resources=(resource,),
        errors=errors,
    )


def test_collect_snapshot_returns_snapshot_on_success():
    mock_client = MagicMock()
    mock_client.subscription_id = "00000000-0000-0000-0000-000000000002"
    mock_client.credential = MagicMock()
    mock_client.tenant_id = "00000000-0000-0000-0000-000000000001"

    expected = _make_snapshot()
    with patch("scanner.graph.snapshot_bridge.ArgInventoryClient") as MockArg:
        instance = MockArg.return_value.__enter__.return_value
        instance.collect.return_value = expected
        result = collect_snapshot(mock_client, "00000000-0000-0000-0000-000000000002")

    assert result is expected


def test_collect_snapshot_returns_none_on_exception():
    mock_client = MagicMock()
    mock_client.tenant_id = "00000000-0000-0000-0000-000000000001"

    with patch("scanner.graph.snapshot_bridge.ArgInventoryClient") as MockArg:
        MockArg.return_value.__enter__.side_effect = Exception("ARG unavailable")
        result = collect_snapshot(mock_client, "00000000-0000-0000-0000-000000000002")

    assert result is None


def test_collect_snapshot_returns_none_when_status_failed():
    mock_client = MagicMock()
    mock_client.tenant_id = "00000000-0000-0000-0000-000000000001"

    failed = _make_snapshot(status=InventoryStatus.FAILED)
    with patch("scanner.graph.snapshot_bridge.ArgInventoryClient") as MockArg:
        instance = MockArg.return_value.__enter__.return_value
        instance.collect.return_value = failed
        result = collect_snapshot(mock_client, "00000000-0000-0000-0000-000000000002")

    assert result is None


def test_collect_snapshot_returns_partial_snapshot():
    mock_client = MagicMock()
    mock_client.tenant_id = "00000000-0000-0000-0000-000000000001"

    partial = _make_snapshot(status=InventoryStatus.PARTIAL, errors=("one page failed",))
    with patch("scanner.graph.snapshot_bridge.ArgInventoryClient") as MockArg:
        instance = MockArg.return_value.__enter__.return_value
        instance.collect.return_value = partial
        result = collect_snapshot(mock_client, "00000000-0000-0000-0000-000000000002")

    assert result is not None
    assert result.status == InventoryStatus.PARTIAL
