"""Verify ScanEngine collects a snapshot and passes it to rules."""
from unittest.mock import MagicMock, patch
import pytest

from scanner.arg_inventory import InventorySnapshot, InventoryStatus
from scanner.engine import ScanEngine


def _make_snapshot():
    return InventorySnapshot(
        snapshot_id="snap-abc",
        tenant_id="00000000-0000-0000-0000-000000000001",
        requested_subscriptions=("00000000-0000-0000-0000-000000000002",),
        status=InventoryStatus.COMPLETE,
        collected_at="2026-09-24T00:00:00+00:00",
        duration_ms=50,
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


def test_run_scan_result_contains_snapshot_id(engine):
    snapshot = _make_snapshot()
    with patch("scanner.engine.collect_snapshot", return_value=snapshot):
        result = engine.run_scan()
    assert result["snapshot_id"] == "snap-abc"
    assert result["snapshot_status"] == "COMPLETE"


def test_run_scan_snapshot_none_when_collection_fails(engine):
    with patch("scanner.engine.collect_snapshot", return_value=None):
        result = engine.run_scan()
    assert result["snapshot_id"] is None
    assert result["snapshot_status"] is None


def test_run_scan_passes_snapshot_to_rule_scan(engine):
    snapshot = _make_snapshot()
    received = {}

    def fake_scan(client, subscription_id, snapshot=None):
        received["snapshot"] = snapshot
        return []

    mock_rule = MagicMock()
    mock_rule.RULE_ID = "AZ-TEST-001"
    mock_rule.SEVERITY = "HIGH"
    mock_rule.scan = fake_scan
    engine.rules = [mock_rule]

    with patch("scanner.engine.collect_snapshot", return_value=snapshot):
        engine.run_scan()

    assert received["snapshot"] is snapshot


def test_run_scan_existing_rule_without_snapshot_param_still_works(engine):
    snapshot = _make_snapshot()

    def legacy_scan(client, subscription_id):
        return [{"rule_id": "AZ-LEGACY-001", "severity": "LOW", "resource_id": "r1",
                 "rule_name": "Legacy", "description": "d", "remediation": "r"}]

    mock_rule = MagicMock()
    mock_rule.RULE_ID = "AZ-LEGACY-001"
    mock_rule.SEVERITY = "LOW"
    mock_rule.scan = legacy_scan
    engine.rules = [mock_rule]

    with patch("scanner.engine.collect_snapshot", return_value=snapshot):
        result = engine.run_scan()

    assert result["total_findings"] == 1
