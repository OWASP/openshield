"""Cross-layer regression tests for finding severity contract v1."""

import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from api.models.finding import DatabaseManager
from openshield.severity import (
    ACCEPTED_SEVERITIES,
    CANONICAL_SEVERITIES,
    CONTRACT_VERSION,
    LEVELS,
    SeverityContractError,
    normalize_severity,
    score_counts,
    score_findings,
    severity_rank,
    severity_risk_score,
    severity_weight,
)
from scanner.engine import ScanEngine

ROOT = Path(__file__).resolve().parents[1]


def _declared_severity(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "SEVERITY":
                    return ast.literal_eval(node.value)
    raise AssertionError(f"{path} has no literal SEVERITY declaration")


def _db() -> DatabaseManager:
    db = DatabaseManager.__new__(DatabaseManager)
    db.dsn = "postgresql://mock/mock"
    db.conn = None
    return db


def _cursor(rows=None):
    cursor = MagicMock()
    cursor.__enter__ = lambda value: value
    cursor.__exit__ = MagicMock(return_value=False)
    cursor.fetchall.return_value = rows or []
    return cursor


def test_contract_v1_is_ordered_and_critical_is_highest():
    assert CONTRACT_VERSION == "1.0.0"
    assert {level.id for level in LEVELS} == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    assert severity_rank("CRITICAL") == max(level.rank for level in LEVELS)
    assert severity_weight("CRITICAL") == 20
    assert severity_risk_score("CRITICAL") == 10
    assert len({level.rank for level in LEVELS}) == len(LEVELS)


def test_aliases_are_canonicalized_and_unknown_values_are_rejected():
    assert "INFORMATIONAL" in ACCEPTED_SEVERITIES
    assert "INFORMATIONAL" not in CANONICAL_SEVERITIES
    assert normalize_severity(" informational ") == "INFO"
    with pytest.raises(SeverityContractError, match="unsupported severity"):
        normalize_severity("urgent")


def test_critical_findings_reduce_score_and_floor_at_zero():
    assert score_findings([{"severity": "CRITICAL"}]) == 80
    assert score_findings([{"severity": "CRITICAL"}] * 5) == 0
    with pytest.raises(SeverityContractError):
        score_findings([{"severity": "unknown"}])
    with pytest.raises(SeverityContractError, match="non-negative integers"):
        score_counts({"CRITICAL": -1})


def test_every_rule_declares_a_canonical_severity():
    rule_paths = sorted((ROOT / "scanner" / "rules").glob("az_*.py"))
    assert rule_paths
    for path in rule_paths:
        assert _declared_severity(path) in CANONICAL_SEVERITIES, path.name


def test_engine_rejects_invalid_finding_severity():
    engine = ScanEngine.__new__(ScanEngine)
    engine.subscription_id = "00000000-0000-0000-0000-000000000000"
    engine.client = MagicMock()
    engine.rules = [
        SimpleNamespace(
            RULE_ID="AZ-TEST-001",
            scan=lambda *_: [{"severity": "URGENT", "rule_id": "AZ-TEST-001"}],
        )
    ]

    with pytest.raises(SeverityContractError):
        engine.run_scan()


def test_engine_publishes_only_canonical_object_findings_without_mutating_rule_data():
    raw_finding = {"severity": "critical", "rule_id": "AZ-TEST-001"}
    engine = ScanEngine.__new__(ScanEngine)
    engine.subscription_id = "00000000-0000-0000-0000-000000000000"
    engine.client = MagicMock()
    engine.rules = [
        SimpleNamespace(
            RULE_ID="AZ-TEST-001",
            scan=lambda *_: ["not-an-object", raw_finding],
        )
    ]

    result = engine.run_scan()

    assert result["total_findings"] == 1
    assert result["findings"][0]["severity"] == "CRITICAL"
    assert result["score"] == 80
    assert result["severity_contract_version"] == CONTRACT_VERSION
    assert raw_finding == {"severity": "critical", "rule_id": "AZ-TEST-001"}


def test_database_score_uses_the_same_critical_weight_as_engine():
    db = _db()
    conn = MagicMock()
    conn.cursor.return_value = _cursor([("CRITICAL", 1)])
    with patch.object(db, "_get_conn", return_value=conn):
        assert db.get_score() == 80


def test_persistence_rejects_invalid_severity_before_opening_connection():
    db = _db()
    result = {
        "scan_id": "00000000-0000-0000-0000-000000000000",
        "subscription_id": "00000000-0000-0000-0000-000000000001",
        "started_at": "2026-08-21T00:00:00+00:00",
        "findings": [{"severity": "URGENT"}],
    }
    with patch.object(db, "_get_conn") as get_conn:
        with pytest.raises(SeverityContractError):
            db.save_scan(result)
    get_conn.assert_not_called()


def test_persistence_canonicalizes_alias_and_records_contract_version():
    db = _db()
    cursor = _cursor()
    conn = MagicMock()
    conn.cursor.return_value = cursor
    raw_finding = {
        # A stale/caller-supplied child ID must never cross-attach a finding.
        "scan_id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "rule_id": "AZ-TEST-001",
        "rule_name": "Test finding",
        "severity": "INFORMATIONAL",
        "category": "Inventory",
        "resource_id": "/subscriptions/test/resources/example",
        "resource_name": "example",
        "resource_type": "Microsoft.Test/resources",
        "description": "Test description",
        "remediation": "Test remediation",
        "playbook": "playbooks/cli/fix_az_test_001.sh",
        "frameworks": {},
        "metadata": {},
        "detected_at": "2026-08-21T00:00:00+00:00",
    }
    result = {
        "scan_id": "00000000-0000-0000-0000-000000000000",
        "subscription_id": "00000000-0000-0000-0000-000000000001",
        "started_at": "2026-08-21T00:00:00+00:00",
        "findings": [raw_finding],
    }

    with patch.object(db, "_get_conn", return_value=conn):
        db.save_scan(result)

    scan_parameters = cursor.execute.call_args_list[0].args[1]
    delete_parameters = cursor.execute.call_args_list[1].args[1]
    finding_parameters = cursor.execute.call_args_list[2].args[1]
    assert scan_parameters[4] == 1
    assert scan_parameters[5] == 100
    assert scan_parameters[10] == CONTRACT_VERSION
    assert delete_parameters == (result["scan_id"],)
    assert finding_parameters[0] == result["scan_id"]
    assert finding_parameters[3] == "INFO"
    assert raw_finding["severity"] == "INFORMATIONAL"
    conn.commit.assert_called_once_with()
    conn.rollback.assert_not_called()


def test_persistence_rolls_back_a_failed_atomic_replacement():
    db = _db()
    cursor = _cursor()
    cursor.execute.side_effect = [None, None, RuntimeError("insert failed")]
    conn = MagicMock()
    conn.cursor.return_value = cursor
    result = {
        "scan_id": "00000000-0000-0000-0000-000000000000",
        "subscription_id": "00000000-0000-0000-0000-000000000001",
        "started_at": "2026-08-21T00:00:00+00:00",
        "findings": [{"rule_id": "AZ-TEST-001", "severity": "HIGH"}],
    }

    with patch.object(db, "_get_conn", return_value=conn):
        with pytest.raises(RuntimeError, match="insert failed"):
            db.save_scan(result)

    conn.rollback.assert_called_once_with()
    conn.commit.assert_not_called()


def test_v1_migration_freezes_the_same_ids_and_weights_as_the_contract():
    migration = (ROOT / "alembic" / "versions" / "d8e4f6a1b2c3_severity_contract_v1.py").read_text(encoding="utf-8")
    for level in LEVELS:
        assert f"WHEN '{level.id}' THEN {level.score_weight}" in migration
        assert f"'{level.id}'" in migration
    assert "severity_contract_version" in migration
    assert "server_default" not in migration


def test_worker_deploy_waits_for_migration_owning_api():
    workflow = (ROOT / ".github" / "workflows" / "deploy.yml").read_text(encoding="utf-8")
    wait_api = workflow.index("- name: Wait for API deployment")
    create_worker = workflow.index("- name: Create worker deployment")
    assert wait_api < create_worker
    assert "continue-on-error" not in workflow[wait_api:create_worker]
