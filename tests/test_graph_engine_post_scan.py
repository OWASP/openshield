"""Tests for post-scan graph population wiring in ScanEngine and worker."""

from unittest.mock import MagicMock, patch
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


def test_snapshot_stored_on_engine_after_run_scan(engine):
    snapshot = _make_snapshot()
    with patch("scanner.engine.collect_snapshot", return_value=snapshot):
        engine.run_scan()
    assert engine.snapshot is snapshot


def test_snapshot_is_none_on_engine_when_collection_fails(engine):
    with patch("scanner.engine.collect_snapshot", return_value=None):
        engine.run_scan()
    assert engine.snapshot is None


def test_scan_result_does_not_call_populate_graph(engine):
    """populate_graph must NOT be called inside run_scan — it belongs in worker."""
    snapshot = _make_snapshot()
    with (
        patch("scanner.engine.collect_snapshot", return_value=snapshot),
        patch("scanner.graph.graph_populator.populate_graph") as mock_populate,
        patch.dict("os.environ", {"DATABASE_URL": "postgresql://test/db"}),
    ):
        engine.run_scan()
    mock_populate.assert_not_called()


def test_scan_succeeds_and_stores_snapshot_even_without_database_url(engine):
    snapshot = _make_snapshot()
    with (
        patch("scanner.engine.collect_snapshot", return_value=snapshot),
        patch.dict("os.environ", {}, clear=True),
    ):
        result = engine.run_scan()
    assert result["status"] == "completed"
    assert engine.snapshot is snapshot


def test_worker_imports_populate_graph():
    """Sanity-check that worker imports populate_graph for post-save invocation."""
    import scanner.worker as worker_module  # noqa: PLC0415

    assert hasattr(worker_module, "populate_graph"), (
        "worker.py must import populate_graph so it can call it after db.save_scan"
    )
