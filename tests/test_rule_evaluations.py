"""Regression tests for the rule evaluation coverage contract (#263).

Covers: the EvaluationStatus/RuleEvaluation contract itself, engine wiring
(legacy rules, evaluator exceptions, evaluate() superseding scan()), the
shared evaluation helpers, and
DatabaseManager persistence of rule_evaluations in the same transaction as
findings.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import scanner.engine as engine_mod
from api.models.finding import DatabaseManager
from scanner.engine import ScanEngine
from scanner.evaluation import (
    EVIDENCE_UNAVAILABLE,
    INVENTORY_UNAVAILABLE,
    NO_RESOURCES_FOUND,
    EvaluationStatus,
    RuleEvaluation,
    aggregate_status,
    fail_findings,
    inventory_unavailable,
    no_resources_found,
    subscription_scope_id,
)

_SUB = "00000000-0000-0000-0000-000000000001"
_SCAN_ID = "00000000-0000-0000-0000-000000000000"
# save_scan only writes while the caller still holds the scan lease (#303).
_OWNER = "worker-under-test"
_TOKEN = 1


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


def test_inventory_unavailable_is_error_at_subscription_scope():
    evaluation = inventory_unavailable("AZ-TEST-010", "Microsoft.Test/things", _SUB)
    assert evaluation.status == EvaluationStatus.ERROR
    assert evaluation.reason_code == INVENTORY_UNAVAILABLE
    assert evaluation.resource_id == subscription_scope_id(_SUB)
    assert evaluation.resource_type == "Microsoft.Test/things"


def test_no_resources_found_is_not_applicable_at_subscription_scope():
    evaluation = no_resources_found("AZ-TEST-011", "Microsoft.Test/things", _SUB)
    assert evaluation.status == EvaluationStatus.NOT_APPLICABLE
    assert evaluation.reason_code == NO_RESOURCES_FOUND
    assert evaluation.resource_id == subscription_scope_id(_SUB)


def test_fail_findings_returns_only_findings_attached_to_fail():
    finding = {"rule_id": "AZ-TEST-012", "resource_id": "/r/1"}
    evaluations = [
        RuleEvaluation(rule_id="AZ-TEST-012", resource_id="/r/1", resource_type="t", status="FAIL", finding=finding),
        RuleEvaluation(rule_id="AZ-TEST-012", resource_id="/r/2", resource_type="t", status="PASS"),
        RuleEvaluation(rule_id="AZ-TEST-012", resource_id="/r/3", resource_type="t", status="UNKNOWN", reason_code="X"),
    ]
    assert fail_findings(evaluations) == [finding]


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


def test_evaluate_supersedes_scan_so_a_violation_is_reported_once(monkeypatch):
    """A rule implementing both scan() and evaluate() is run through evaluate()
    only, so a violation both would report is counted once."""
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


def _finding(rule_id: str, resource_id: str) -> dict:
    return {
        "rule_id": rule_id,
        "rule_name": "Test",
        "severity": "HIGH",
        "category": "Test",
        "resource_id": resource_id,
        "resource_name": "r",
        "resource_type": "Microsoft.Test/resources",
        "description": "d",
        "remediation": "r",
        "playbook": "playbooks/cli/fix.sh",
        "frameworks": {},
        "metadata": {},
    }


def _engine(rules) -> ScanEngine:
    eng = ScanEngine.__new__(ScanEngine)
    eng.subscription_id = _SUB
    eng.client = MagicMock()
    eng.rules = rules
    return eng


def test_engine_does_not_call_scan_for_a_rule_with_evaluate(monkeypatch):
    """evaluate() supersedes scan(); calling both repeats every Azure list call."""
    _patch_engine_client(monkeypatch, MagicMock())
    scan = MagicMock(return_value=[])
    rule = SimpleNamespace(
        RULE_ID="AZ-TEST-020",
        scan=scan,
        evaluate=lambda *_: [no_resources_found("AZ-TEST-020", "Microsoft.Test/resources", _SUB)],
    )

    result = _engine([rule]).run_scan()

    scan.assert_not_called()
    assert result["evaluations"][0]["status"] == EvaluationStatus.NOT_APPLICABLE
    assert result["failed_rule_ids"] == []


def test_engine_records_a_crashed_evaluate_as_a_failed_rule(monkeypatch):
    """With scan() no longer run, an evaluate() crash is the rule failing to
    complete and must reach failed_rule_ids, not just an ERROR row."""
    _patch_engine_client(monkeypatch, MagicMock())

    def _boom(*_args):
        raise RuntimeError("evaluator blew up")

    result = _engine([SimpleNamespace(RULE_ID="AZ-TEST-021", scan=lambda *_: [], evaluate=_boom)]).run_scan()

    assert result["failed_rule_ids"] == ["AZ-TEST-021"]


def test_engine_records_an_error_evaluation_as_a_failed_rule(monkeypatch):
    """A rule whose inventory call failed inspected nothing; failed_rule_ids
    must agree with its ERROR evaluation instead of reading as completed."""
    _patch_engine_client(monkeypatch, MagicMock())
    rule = SimpleNamespace(
        RULE_ID="AZ-TEST-025",
        scan=lambda *_: [],
        evaluate=lambda *_: [inventory_unavailable("AZ-TEST-025", "Microsoft.Test/resources", _SUB)],
    )

    result = _engine([rule]).run_scan()

    assert result["evaluations"][0]["reason_code"] == INVENTORY_UNAVAILABLE
    assert result["failed_rule_ids"] == ["AZ-TEST-025"]


def test_engine_does_not_fail_a_rule_for_partial_error_when_other_resources_passed(monkeypatch):
    """A partial inventory failure does not make a rule with usable outcomes
    a total failure; the ERROR and PASS rows are both preserved."""
    _patch_engine_client(monkeypatch, MagicMock())

    def _evaluate(*_args):
        return [
            RuleEvaluation(rule_id="AZ-TEST-026", resource_id="/r/1", resource_type="t", status=EvaluationStatus.PASS),
            inventory_unavailable("AZ-TEST-026", "Microsoft.Test/second", _SUB),
        ]

    result = _engine([SimpleNamespace(RULE_ID="AZ-TEST-026", scan=lambda *_: [], evaluate=_evaluate)]).run_scan()

    assert result["failed_rule_ids"] == []
    assert [e["status"] for e in result["evaluations"]] == [EvaluationStatus.PASS, EvaluationStatus.ERROR]


def test_engine_does_not_fail_a_rule_for_per_resource_error_when_another_passes(monkeypatch):
    """A per-resource ERROR is retained but does not fail the rule if another
    resource produced a usable result."""
    _patch_engine_client(monkeypatch, MagicMock())
    rule_id = "AZ-TEST-029"

    def _evaluate(*_args):
        return [
            RuleEvaluation(rule_id=rule_id, resource_id="/r/1", resource_type="t", status=EvaluationStatus.PASS),
            RuleEvaluation(
                rule_id=rule_id,
                resource_id="/r/2",
                resource_type="t",
                status=EvaluationStatus.ERROR,
                reason_code="RESOURCE_EVALUATION_ERROR",
                reason="Evidence lookup failed for this resource.",
            ),
        ]

    result = _engine([SimpleNamespace(RULE_ID=rule_id, evaluate=_evaluate)]).run_scan()

    assert [e["status"] for e in result["evaluations"]] == [EvaluationStatus.PASS, EvaluationStatus.ERROR]
    assert result["failed_rule_ids"] == []


def test_engine_fails_a_rule_when_every_per_resource_outcome_is_error(monkeypatch):
    """All-error resource outcomes supply no usable coverage and count as a
    total rule failure, even when the inventory itself was available."""
    _patch_engine_client(monkeypatch, MagicMock())
    rule_id = "AZ-TEST-030"

    def _evaluate(*_args):
        return [
            RuleEvaluation(
                rule_id=rule_id,
                resource_id=f"/r/{index}",
                resource_type="t",
                status=EvaluationStatus.ERROR,
                reason_code="RESOURCE_EVALUATION_ERROR",
                reason="Evidence lookup failed for this resource.",
            )
            for index in range(2)
        ]

    result = _engine([SimpleNamespace(RULE_ID=rule_id, evaluate=_evaluate)]).run_scan()

    assert [e["status"] for e in result["evaluations"]] == [EvaluationStatus.ERROR, EvaluationStatus.ERROR]
    assert result["failed_rule_ids"] == [rule_id]


def test_engine_does_not_list_a_rule_for_per_resource_unknown(monkeypatch):
    """Evidence missing for some resources is UNKNOWN, not ERROR: a rule that
    evaluated 8 resources and could not read 2 completed and is not listed."""
    _patch_engine_client(monkeypatch, MagicMock())

    def _evaluate(*_args):
        passed = [
            RuleEvaluation(
                rule_id="AZ-TEST-027", resource_id=f"/r/{i}", resource_type="t", status=EvaluationStatus.PASS
            )
            for i in range(8)
        ]
        unknown = [
            RuleEvaluation(
                rule_id="AZ-TEST-027",
                resource_id=f"/r/{i}",
                resource_type="t",
                status=EvaluationStatus.UNKNOWN,
                reason_code=EVIDENCE_UNAVAILABLE,
            )
            for i in range(8, 10)
        ]
        return passed + unknown

    result = _engine([SimpleNamespace(RULE_ID="AZ-TEST-027", scan=lambda *_: [], evaluate=_evaluate)]).run_scan()

    assert result["failed_rule_ids"] == []
    assert len(result["evaluations"]) == 10


def test_engine_keeps_valid_evaluations_and_findings_when_some_items_are_malformed(monkeypatch):
    """Dropping the whole list on one bad item would also drop real FAIL
    findings; keep the valid evaluations and add one ERROR naming the bad items."""
    _patch_engine_client(monkeypatch, MagicMock())
    resource_id = "/subscriptions/x/resource/1"

    def _evaluate(*_args):
        return [
            RuleEvaluation(
                rule_id="AZ-TEST-028",
                resource_id=resource_id,
                resource_type="Microsoft.Test/resources",
                status=EvaluationStatus.FAIL,
                finding=_finding("AZ-TEST-028", resource_id),
            ),
            {"status": "PASS"},
            RuleEvaluation(rule_id="AZ-TEST-028", resource_id="/r/2", resource_type="t", status=EvaluationStatus.PASS),
            None,
        ]

    result = _engine([SimpleNamespace(RULE_ID="AZ-TEST-028", scan=lambda *_: [], evaluate=_evaluate)]).run_scan()

    statuses = [e["status"] for e in result["evaluations"]]
    assert statuses == [EvaluationStatus.FAIL, EvaluationStatus.PASS, EvaluationStatus.ERROR]
    error = result["evaluations"][-1]
    assert error["reason_code"] == "MALFORMED_EVALUATION"
    assert "#1 (dict)" in error["reason"] and "#3 (NoneType)" in error["reason"]
    assert result["total_findings"] == 1
    assert result["findings"][0]["resource_id"] == resource_id
    assert result["failed_rule_ids"] == ["AZ-TEST-028"]


def test_engine_rejects_evaluate_items_that_are_not_rule_evaluations(monkeypatch):
    """A malformed item must become an ERROR for that rule instead of failing
    the whole scan when results are serialised."""
    _patch_engine_client(monkeypatch, MagicMock())
    rule = SimpleNamespace(RULE_ID="AZ-TEST-022", scan=lambda *_: [], evaluate=lambda *_: [{"status": "PASS"}])

    result = _engine([rule]).run_scan()

    assert len(result["evaluations"]) == 1
    assert result["evaluations"][0]["status"] == EvaluationStatus.ERROR
    assert result["evaluations"][0]["reason_code"] == "MALFORMED_EVALUATION"
    assert result["failed_rule_ids"] == ["AZ-TEST-022"]


def test_engine_reports_one_finding_per_resource_for_repeated_fail(monkeypatch):
    _patch_engine_client(monkeypatch, MagicMock())
    resource_id = "/subscriptions/x/resource/1"

    def _evaluate(*_args):
        return [
            RuleEvaluation(
                rule_id="AZ-TEST-023",
                resource_id=resource_id,
                resource_type="Microsoft.Test/resources",
                status=EvaluationStatus.FAIL,
                finding=_finding("AZ-TEST-023", resource_id),
            )
            for _ in range(2)
        ]

    result = _engine([SimpleNamespace(RULE_ID="AZ-TEST-023", scan=lambda *_: [], evaluate=_evaluate)]).run_scan()

    assert result["total_findings"] == 1


def test_engine_skips_a_fail_evaluation_without_a_finding(monkeypatch, caplog):
    _patch_engine_client(monkeypatch, MagicMock())
    rule = SimpleNamespace(
        RULE_ID="AZ-TEST-024",
        scan=lambda *_: [],
        evaluate=lambda *_: [
            RuleEvaluation(
                rule_id="AZ-TEST-024",
                resource_id="/subscriptions/x/resource/1",
                resource_type="Microsoft.Test/resources",
                status=EvaluationStatus.FAIL,
            )
        ],
    )

    result = _engine([rule]).run_scan()

    assert result["total_findings"] == 0
    assert result["evaluations"][0]["status"] == EvaluationStatus.FAIL
    assert "without a finding" in caplog.text


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
    last_sql = {"text": ""}

    def _execute(sql, *args, **kwargs):
        last_sql["text"] = sql
        return MagicMock()

    def _fetchone():
        # save_scan opens with the lease/fencing ownership probe. It must see
        # an owned row, and it must not consume a finding id -- the linkage
        # assertions below depend on findings starting at 1.
        if "FOR UPDATE" in last_sql["text"]:
            return (_SCAN_ID,)
        return (next(ids),)

    cur.execute.side_effect = _execute
    cur.fetchone.side_effect = _fetchone
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
        db.save_scan(result, _OWNER, _TOKEN)

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
        db.save_scan(result, _OWNER, _TOKEN)

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
        db.save_scan(result, _OWNER, _TOKEN)

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
        db.save_scan(result, _OWNER, _TOKEN)  # must not raise
