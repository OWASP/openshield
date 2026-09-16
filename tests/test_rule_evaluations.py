"""Regression tests for the rule evaluation coverage contract (#263).

Covers: the EvaluationStatus/RuleEvaluation contract itself, engine wiring
(legacy rules, evaluator exceptions, FAIL-finding dedup against scan()), and
DatabaseManager persistence of rule_evaluations in the same transaction as
findings.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import scanner.engine as engine_mod
from api.models.finding import DatabaseManager
from scanner.engine import ScanEngine
from scanner.evaluation import EvaluationStatus, RuleEvaluation, aggregate_status, subscription_scope_id

_SUB = "00000000-0000-0000-0000-000000000001"


# ── RuleEvaluation / EvaluationStatus contract ──────────────────────────────


def test_rule_evaluation_rejects_unknown_status():
    with pytest.raises(ValueError, match="unsupported evaluation status"):
        RuleEvaluation(rule_id="AZ-TEST-001", resource_id="/subscriptions/x", resource_type="", status="BOGUS")


def test_rule_evaluation_rejects_empty_resource_id():
    with pytest.raises(ValueError, match="non-empty canonical identifier"):
        RuleEvaluation(rule_id="AZ-TEST-001", resource_id="", resource_type="", status=EvaluationStatus.PASS)


@pytest.mark.parametrize("status", [EvaluationStatus.UNKNOWN, EvaluationStatus.ERROR, EvaluationStatus.NOT_APPLICABLE])
def test_rule_evaluation_requires_reason_code_for_non_terminal_statuses(status):
    with pytest.raises(ValueError, match="requires a reason_code"):
        RuleEvaluation(rule_id="AZ-TEST-001", resource_id="/subscriptions/x", resource_type="", status=status)


def test_subscription_scope_id_is_non_empty_and_stable():
    scope = subscription_scope_id(_SUB)
    assert scope == f"/subscriptions/{_SUB}"


def test_aggregate_status_conservative_order():
    # FAIL > ERROR > UNKNOWN > PASS > NOT_APPLICABLE regardless of input order.
    assert aggregate_status(["PASS", "FAIL", "UNKNOWN"]) == "FAIL"
    assert aggregate_status(["PASS", "ERROR"]) == "ERROR"
    assert aggregate_status(["PASS", "UNKNOWN"]) == "UNKNOWN"
    assert aggregate_status(["NOT_APPLICABLE", "PASS"]) == "PASS"
    assert aggregate_status(["NOT_APPLICABLE"]) == "NOT_APPLICABLE"


def test_aggregate_status_requires_at_least_one():
    with pytest.raises(ValueError):
        aggregate_status([])


# ── Engine wiring ────────────────────────────────────────────────────────────


def _patch_engine_client(monkeypatch, client):
    monkeypatch.setattr(engine_mod, "AzureClient", lambda subscription_id: client)


def test_legacy_rule_without_evaluate_is_recorded_as_unknown(monkeypatch):
    """A rule with only scan() must never contribute a PASS — its coverage is
    UNKNOWN/LEGACY_RULE_NOT_MIGRATED, not silently absent."""
    _patch_engine_client(monkeypatch, MagicMock())
    eng = ScanEngine.__new__(ScanEngine)
    eng.subscription_id = _SUB
    eng.client = MagicMock()
    eng.rules = [SimpleNamespace(RULE_ID="AZ-TEST-001", scan=lambda *_: [])]

    result = eng.run_scan()

    evaluations = result["evaluations"]
    assert len(evaluations) == 1
    assert evaluations[0]["status"] == EvaluationStatus.UNKNOWN
    assert evaluations[0]["reason_code"] == "LEGACY_RULE_NOT_MIGRATED"
    assert evaluations[0]["resource_id"] == subscription_scope_id(_SUB)


def test_evaluate_exception_produces_error_at_canonical_scope(monkeypatch):
    """A rule whose evaluate() raises must still produce a coverage row (ERROR),
    not silently vanish the way a bare scan() exception does."""
    _patch_engine_client(monkeypatch, MagicMock())
    eng = ScanEngine.__new__(ScanEngine)
    eng.subscription_id = _SUB
    eng.client = MagicMock()

    def _boom(*_args, **_kwargs):
        raise RuntimeError("evaluator blew up")

    eng.rules = [SimpleNamespace(RULE_ID="AZ-TEST-002", scan=lambda *_: [], evaluate=_boom)]

    result = eng.run_scan()  # must not raise

    evaluations = result["evaluations"]
    assert len(evaluations) == 1
    assert evaluations[0]["status"] == EvaluationStatus.ERROR
    assert evaluations[0]["reason_code"] == "EVALUATOR_EXCEPTION"
    assert evaluations[0]["resource_id"] == subscription_scope_id(_SUB)


def test_evaluate_must_return_a_list(monkeypatch):
    """A non-list return from evaluate() is treated the same as a raised
    exception (ERROR), not silently accepted or crashed on."""
    _patch_engine_client(monkeypatch, MagicMock())
    eng = ScanEngine.__new__(ScanEngine)
    eng.subscription_id = _SUB
    eng.client = MagicMock()
    eng.rules = [SimpleNamespace(RULE_ID="AZ-TEST-003", scan=lambda *_: [], evaluate=lambda *_: "not-a-list")]

    result = eng.run_scan()

    assert result["evaluations"][0]["status"] == EvaluationStatus.ERROR
    assert result["evaluations"][0]["reason_code"] == "EVALUATOR_EXCEPTION"


def test_fail_evaluation_contributes_finding_when_scan_did_not_already_report_it(monkeypatch):
    """A rule that is evaluate()-only (no matching scan() finding) must still
    have its FAIL surfaced as a real finding, not just a status row."""
    _patch_engine_client(monkeypatch, MagicMock())
    eng = ScanEngine.__new__(ScanEngine)
    eng.subscription_id = _SUB
    eng.client = MagicMock()

    finding = {
        "rule_id": "AZ-TEST-004",
        "rule_name": "Test",
        "severity": "HIGH",
        "category": "Test",
        "resource_id": "/subscriptions/x/resource/1",
        "resource_name": "r1",
        "resource_type": "Microsoft.Test/resources",
        "description": "d",
        "remediation": "r",
        "playbook": "playbooks/cli/fix_az_test_004.sh",
        "frameworks": {},
        "metadata": {},
    }
    eng.rules = [
        SimpleNamespace(
            RULE_ID="AZ-TEST-004",
            scan=lambda *_: [],
            evaluate=lambda *_: [
                RuleEvaluation(
                    rule_id="AZ-TEST-004",
                    resource_id=finding["resource_id"],
                    resource_type=finding["resource_type"],
                    status=EvaluationStatus.FAIL,
                    finding=finding,
                )
            ],
        )
    ]

    result = eng.run_scan()

    assert result["total_findings"] == 1
    assert result["findings"][0]["resource_id"] == finding["resource_id"]


def test_fail_evaluation_does_not_duplicate_a_finding_scan_already_reported(monkeypatch):
    """A rule implementing both scan() and evaluate() must not double-count a
    violation both already agree on."""
    _patch_engine_client(monkeypatch, MagicMock())
    eng = ScanEngine.__new__(ScanEngine)
    eng.subscription_id = _SUB
    eng.client = MagicMock()

    shared = {
        "rule_id": "AZ-TEST-005",
        "rule_name": "Test",
        "severity": "HIGH",
        "category": "Test",
        "resource_id": "/subscriptions/x/resource/1",
        "resource_name": "r1",
        "resource_type": "Microsoft.Test/resources",
        "description": "d",
        "remediation": "r",
        "playbook": "playbooks/cli/fix_az_test_005.sh",
        "frameworks": {},
        "metadata": {},
    }
    eng.rules = [
        SimpleNamespace(
            RULE_ID="AZ-TEST-005",
            scan=lambda *_: [dict(shared)],
            evaluate=lambda *_: [
                RuleEvaluation(
                    rule_id="AZ-TEST-005",
                    resource_id=shared["resource_id"],
                    resource_type=shared["resource_type"],
                    status=EvaluationStatus.FAIL,
                    finding=dict(shared),
                )
            ],
        )
    ]

    result = eng.run_scan()

    assert result["total_findings"] == 1


# ── Persistence: rule_evaluations written in the same transaction ──────────


def _db() -> DatabaseManager:
    db = DatabaseManager.__new__(DatabaseManager)
    db.dsn = "postgresql://mock/mock"
    db.conn = None
    return db


def _cursor():
    cur = MagicMock()
    cur.__enter__ = lambda s: s
    cur.__exit__ = MagicMock(return_value=False)
    # Every INSERT ... RETURNING id call returns an incrementing fake id.
    ids = iter(range(1, 10_000))
    cur.fetchone.side_effect = lambda: (next(ids),)
    return cur


def test_save_scan_persists_evaluations_and_links_fail_finding_id():
    db = _db()
    cursor = _cursor()
    conn = MagicMock()
    conn.cursor.return_value = cursor

    finding = {
        "rule_id": "AZ-TEST-006",
        "rule_name": "Test",
        "severity": "HIGH",
        "category": "Test",
        "resource_id": "/subscriptions/x/resource/1",
        "resource_name": "r1",
        "resource_type": "Microsoft.Test/resources",
        "description": "d",
        "remediation": "r",
        "playbook": "playbooks/cli/fix_az_test_006.sh",
        "frameworks": {},
        "metadata": {},
        "detected_at": "2026-08-29T00:00:00+00:00",
    }
    result = {
        "scan_id": "00000000-0000-0000-0000-000000000000",
        "subscription_id": _SUB,
        "started_at": "2026-08-29T00:00:00+00:00",
        "findings": [finding],
        "evaluations": [
            {
                "rule_id": "AZ-TEST-006",
                "resource_id": finding["resource_id"],
                "resource_type": finding["resource_type"],
                "status": "FAIL",
                "reason_code": None,
                "reason": None,
                "evidence": {},
            },
            {
                "rule_id": "AZ-TEST-007",
                "resource_id": subscription_scope_id(_SUB),
                "resource_type": "",
                "status": "UNKNOWN",
                "reason_code": "LEGACY_RULE_NOT_MIGRATED",
                "reason": "not migrated",
                "evidence": {},
            },
        ],
    }

    with patch.object(db, "_get_conn", return_value=conn):
        db.save_scan(result)

    insert_calls = [c for c in cursor.execute.call_args_list if "INSERT INTO rule_evaluations" in c.args[0]]
    assert len(insert_calls) == 2

    fail_call_params = insert_calls[0].args[1]
    # (scan_id, rule_id, resource_id, resource_type, status, reason_code, reason, evidence, finding_id, evaluated_at)
    assert fail_call_params[1] == "AZ-TEST-006"
    assert fail_call_params[4] == "FAIL"
    assert fail_call_params[8] == 1  # linked to the finding's returned id

    unknown_call_params = insert_calls[1].args[1]
    assert unknown_call_params[4] == "UNKNOWN"
    assert unknown_call_params[8] is None  # never linked to a finding


def test_save_scan_evaluations_upsert_on_conflict_instead_of_delete_first():
    """A retried/replayed scan result must converge on the same rows via
    ON CONFLICT, not a delete-then-reinsert that could momentarily leave a
    concurrent reader seeing zero coverage for an already-covered scan."""
    db = _db()
    cursor = _cursor()
    conn = MagicMock()
    conn.cursor.return_value = cursor

    result = {
        "scan_id": "00000000-0000-0000-0000-000000000000",
        "subscription_id": _SUB,
        "started_at": "2026-08-29T00:00:00+00:00",
        "findings": [],
        "evaluations": [
            {
                "rule_id": "AZ-TEST-008",
                "resource_id": subscription_scope_id(_SUB),
                "resource_type": "",
                "status": "PASS",
            }
        ],
    }

    with patch.object(db, "_get_conn", return_value=conn):
        db.save_scan(result)

    insert_calls = [c for c in cursor.execute.call_args_list if "INSERT INTO rule_evaluations" in c.args[0]]
    assert len(insert_calls) == 1
    assert "ON CONFLICT (scan_id, rule_id, resource_id) DO UPDATE" in insert_calls[0].args[0]

    delete_calls = [
        c for c in cursor.execute.call_args_list if c.args[0].strip().startswith("DELETE FROM rule_evaluations")
    ]
    assert len(delete_calls) == 1
    # delete-absent, scoped by the current evaluation set, not a blanket delete.
    assert "NOT IN" in delete_calls[0].args[0]
    assert delete_calls[0].args[1] == (result["scan_id"], ["AZ-TEST-008"], [subscription_scope_id(_SUB)])


def test_save_scan_deletes_all_prior_evaluations_when_scan_reports_none():
    """A scan whose evaluations list is genuinely empty this time must still
    clear out any stale rows from a prior attempt for the same scan_id."""
    db = _db()
    cursor = _cursor()
    conn = MagicMock()
    conn.cursor.return_value = cursor

    result = {
        "scan_id": "00000000-0000-0000-0000-000000000000",
        "subscription_id": _SUB,
        "started_at": "2026-08-29T00:00:00+00:00",
        "findings": [],
        "evaluations": [],
    }

    with patch.object(db, "_get_conn", return_value=conn):
        db.save_scan(result)

    delete_sql = [c.args[0] for c in cursor.execute.call_args_list if c.args[0].strip().startswith("DELETE")]
    assert any("rule_evaluations" in sql for sql in delete_sql)


def test_save_scan_evaluations_default_to_empty_list_for_backward_compatible_callers():
    """A caller that doesn't pass 'evaluations' (pre-#263 code paths, existing
    tests) must not crash save_scan."""
    db = _db()
    cursor = _cursor()
    conn = MagicMock()
    conn.cursor.return_value = cursor

    result = {
        "scan_id": "00000000-0000-0000-0000-000000000000",
        "subscription_id": _SUB,
        "started_at": "2026-08-29T00:00:00+00:00",
        "findings": [],
    }

    with patch.object(db, "_get_conn", return_value=conn):
        db.save_scan(result)  # must not raise
