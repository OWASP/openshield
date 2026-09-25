"""Tests for post-scan graph population wiring in ScanEngine."""

from unittest.mock import patch
import pytest

from scanner.engine import ScanEngine
from scanner.arg_inventory import InventorySnapshot, InventoryStatus


def _make_snapshot():
    return InventorySnapshot(
        snapshot_id="snap-1",
        tenant_id="00000000-0000-0000-0000-000000000001",
        requested_subscriptions=("00000000-0000-0000-0000-000000000002",),
        status=InventoryStatus.COMPLETE,
        collected_at="2026-09-24T00:00:00+00:00",
        duration_ms=10,
        pages=1,
        resources=(),
        errors=(),
    )


@pytest.fixture
def engine():
    with patch("scanner.engine.AzureClient"), patch("scanner.engine.ScanEngine.load_rules"):
        eng = ScanEngine("00000000-0000-0000-0000-000000000002")
        eng.rules = []
        return eng


def test_populate_graph_called_when_snapshot_and_dsn_available(engine):
    snapshot = _make_snapshot()
    with (
        patch("scanner.engine.collect_snapshot", return_value=snapshot),
        patch("scanner.engine.populate_graph") as mock_populate,
        patch.dict("os.environ", {"DATABASE_URL": "postgresql://test/db"}),
    ):
        engine.run_scan()
    mock_populate.assert_called_once()


def test_populate_graph_not_called_when_snapshot_none(engine):
    with (
        patch("scanner.engine.collect_snapshot", return_value=None),
        patch("scanner.engine.populate_graph") as mock_populate,
        patch.dict("os.environ", {"DATABASE_URL": "postgresql://test/db"}),
    ):
        engine.run_scan()
    mock_populate.assert_not_called()


def test_populate_graph_not_called_when_no_database_url(engine):
    snapshot = _make_snapshot()
    with (
        patch("scanner.engine.collect_snapshot", return_value=snapshot),
        patch("scanner.engine.populate_graph") as mock_populate,
        patch.dict("os.environ", {}, clear=True),
    ):
        engine.run_scan()
    mock_populate.assert_not_called()


def test_scan_succeeds_even_if_populate_graph_raises(engine):
    snapshot = _make_snapshot()
    with (
        patch("scanner.engine.collect_snapshot", return_value=snapshot),
        patch("scanner.engine.populate_graph", side_effect=Exception("DB down")),
        patch.dict("os.environ", {"DATABASE_URL": "postgresql://test/db"}),
    ):
        result = engine.run_scan()
    assert result["status"] == "completed"
