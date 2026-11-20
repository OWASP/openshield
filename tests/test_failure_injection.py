"""Shared failure-injection scenarios for the evaluate() coverage contract (#389).

Every rule exposing ``evaluate()`` is discovered the same way the engine and
``test_rule_evaluation_contract.py`` do, so each rule-family migration inherits
these scenarios without adding tests of its own. Each scenario injects one
Azure failure mode through a mock client, runs the rule through
``ScanEngine.run_scan()`` and then through ``get_compliance_score()``, and
asserts that incomplete evidence never becomes a clean PASS.

The scenario matrix is documented in ``docs/failure-scenario-matrix.md``.
Everything here is offline: no Azure credentials and no database.
"""

import importlib
from pathlib import Path
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import pytest

import api.models.finding as finding_module
import scanner.engine as engine_mod
from scanner.engine import ScanEngine
from scanner.evaluation import (
    EVIDENCE_UNAVAILABLE,
    INVENTORY_UNAVAILABLE,
    MISSING_PROPERTIES,
    NO_RESOURCES_FOUND,
    EvaluationStatus,
)
from tests.helpers.mock_azure import MockAzureClient, make_resource

_SUB = "00000000-0000-0000-0000-000000000001"
_OTHER_SUB = "00000000-0000-0000-0000-000000000002"
_RULES_DIR = Path(__file__).resolve().parent.parent / "scanner" / "rules"


def _migrated_rules():
    modules = []
    for path in sorted(_RULES_DIR.glob("az_*.py")):
        module = importlib.import_module(f"scanner.rules.{path.stem}")
        if callable(getattr(module, "evaluate", None)):
            modules.append(module)
    return modules


MIGRATED = _migrated_rules()


def _ids(module: Any) -> str:
    return module.RULE_ID


# ── Fault injection ─────────────────────────────────────────────────────────


class _OfflineCredential:
    def get_token(self, *scopes, **kwargs):
        raise RuntimeError("offline test: no Azure access")


class _FaultClient(MockAzureClient):
    """Every inventory and lookup call goes through ``behaviour``.

    The behaviour is either a value to return (``None`` is how AzureClient
    reports a failed list call, ``[]`` an empty inventory) or an exception
    to raise, which is how an unwrapped permission, timeout or throttling
    failure reaches a rule.
    """

    def __init__(self, behaviour: Any) -> None:
        super().__init__()
        self.credential = _OfflineCredential()
        self._behaviour = behaviour

    def __getattribute__(self, name: str) -> Any:
        if name.startswith(("list_", "get_")):
            behaviour = object.__getattribute__(self, "_behaviour")

            def call(*args: Any, **kwargs: Any) -> Any:
                if isinstance(behaviour, BaseException):
                    raise behaviour
                return behaviour

            return call
        return object.__getattribute__(self, name)


# One row per failure mode that must not read as compliant. ``rule_failed``
# says whether the engine must list the rule in ``failed_rule_ids``.
# (behaviour, expected statuses, expected reason code, rule listed in failed_rule_ids)
SCENARIOS = {
    "collection_failed_returns_none": (None, {EvaluationStatus.ERROR}, INVENTORY_UNAVAILABLE, True),
    "permission_denied": (
        PermissionError("AuthorizationFailed"),
        {EvaluationStatus.ERROR},
        "EVALUATOR_EXCEPTION",
        True,
    ),
    "timeout": (TimeoutError("read timed out"), {EvaluationStatus.ERROR}, "EVALUATOR_EXCEPTION", True),
    "throttling_retries_exhausted": (
        RuntimeError("429 TooManyRequests, retries exhausted"),
        {EvaluationStatus.ERROR},
        "EVALUATOR_EXCEPTION",
        True,
    ),
    "successful_empty_inventory": ([], {EvaluationStatus.NOT_APPLICABLE}, NO_RESOURCES_FOUND, False),
}


def _scan(rule: Any, client: MockAzureClient, monkeypatch: pytest.MonkeyPatch, subscription_id: str = _SUB) -> dict:
    monkeypatch.setattr(engine_mod, "AzureClient", lambda sid: client)
    engine = ScanEngine(subscription_id)
    engine.rules = [rule]
    return engine.run_scan()


def _control_status(result: dict, rule_id: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """Status of ``rule_id``'s control as the compliance report derives it."""
    import json

    control = {
        "control_id": "T.1",
        "control_name": "Test control",
        "description": "test",
        "mapping_type": "direct",
        "evidence_type": "automated_configuration_scan",
        "primary_source": "test source",
        "rationale": "test rationale",
        "owner": "Test reviewer",
        "review_status": "reviewed",
        "review_date": "2026-08-22",
    }
    pack = {
        "framework": "Test Framework",
        "version": "1.0",
        "published": "2026-01",
        "mapping_pack_version": "1.0.0",
        "mapping_pack_status": "current",
        "mapping_pack_source": "test fixture",
        "mapping_pack_published": "2026-08-22",
        "controls": {rule_id: control},
    }
    (tmp_path / "fw.json").write_text(json.dumps(pack), encoding="utf-8")
    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "failurefw", "fw.json")

    cursor = MagicMock()
    cursor.__enter__ = lambda s: s
    cursor.__exit__ = MagicMock(return_value=False)
    cursor.fetchone.return_value = {
        "scan_id": result["scan_id"],
        "compliance_mapping_snapshot": {"_scan_rule_outcomes": {"failed_rule_ids": result["failed_rule_ids"]}},
    }
    state = {"sql": ""}
    evaluation_rows = [(e["rule_id"], e["status"]) for e in result["evaluations"]]
    finding_rows = [(f["rule_id"], f["severity"], f["category"], 1) for f in result["findings"]]
    cursor.execute.side_effect = lambda sql, *a, **k: state.update(sql=sql)
    cursor.fetchall.side_effect = lambda: evaluation_rows if "rule_evaluations" in state["sql"] else finding_rows
    conn = MagicMock()
    conn.cursor.return_value = cursor

    db = finding_module.DatabaseManager.__new__(finding_module.DatabaseManager)
    db.dsn = "postgresql://mock/mock"
    db.conn = None
    with patch.object(db, "_get_conn", return_value=conn):
        report = db.get_compliance_score("failurefw")
    return report["controls"][0]["status"]


# ── Scenarios that apply to every migrated rule ─────────────────────────────


def test_at_least_one_rule_is_migrated():
    assert MIGRATED, "no rule exposes evaluate(); the scenarios below would silently check nothing"


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
@pytest.mark.parametrize("rule", MIGRATED, ids=_ids)
def test_failure_mode_never_becomes_pass_or_a_finding(rule, scenario, monkeypatch, tmp_path):
    behaviour, expected_statuses, reason_code, rule_failed = SCENARIOS[scenario]

    result = _scan(rule, _FaultClient(behaviour), monkeypatch)

    statuses = {e["status"] for e in result["evaluations"]}
    reason_codes = {e["reason_code"] for e in result["evaluations"]}
    assert statuses == expected_statuses
    assert reason_code in reason_codes
    assert result["findings"] == []
    assert (rule.RULE_ID in result["failed_rule_ids"]) is rule_failed

    control_status = _control_status(result, rule.RULE_ID, tmp_path, monkeypatch)
    expected_control = (
        EvaluationStatus.NOT_APPLICABLE if statuses == {EvaluationStatus.NOT_APPLICABLE} else EvaluationStatus.ERROR
    )
    assert control_status == expected_control
    assert control_status != EvaluationStatus.PASS


@pytest.mark.parametrize("rule", MIGRATED, ids=_ids)
def test_empty_inventory_is_distinct_from_collection_failure(rule, monkeypatch):
    empty = _scan(rule, _FaultClient([]), monkeypatch)
    failed = _scan(rule, _FaultClient(None), monkeypatch)

    assert {e["status"] for e in empty["evaluations"]} == {EvaluationStatus.NOT_APPLICABLE}
    assert {e["status"] for e in failed["evaluations"]} == {EvaluationStatus.ERROR}
    assert rule.RULE_ID not in empty["failed_rule_ids"]
    assert rule.RULE_ID in failed["failed_rule_ids"]


@pytest.mark.parametrize("rule", MIGRATED, ids=_ids)
def test_malformed_evaluate_output_is_a_failed_rule_not_a_clean_one(rule, monkeypatch):
    class _Malformed:
        RULE_ID = rule.RULE_ID

        @staticmethod
        def evaluate(client: Any, subscription_id: str) -> Any:
            return [{"status": "PASS"}]

    result = _scan(_Malformed, _FaultClient(None), monkeypatch)

    assert rule.RULE_ID in result["failed_rule_ids"]
    assert EvaluationStatus.PASS not in {e["status"] for e in result["evaluations"]}


@pytest.mark.parametrize("rule", MIGRATED, ids=_ids)
def test_evaluations_stay_scoped_to_the_scanned_subscription(rule, monkeypatch):
    result = _scan(rule, _FaultClient(None), monkeypatch, subscription_id=_OTHER_SUB)

    assert result["subscription_id"] == _OTHER_SUB
    for evaluation in result["evaluations"]:
        assert evaluation["resource_id"].startswith(f"/subscriptions/{_OTHER_SUB}")
        assert _SUB not in evaluation["resource_id"]


# ── Partial evidence, shown through AZ-KV-006 ───────────────────────────────
# A rule-specific scenario: it needs a real resource shape, so it is written
# against one migrated rule. Add the same pattern next to a rule family's
# tests when a migration introduces a new partial-evidence path.


def _vault(name: str, properties: Optional[Any]) -> Any:
    return make_resource(
        id=f"/subscriptions/{_SUB}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/{name}",
        name=name,
        location="eastus",
        properties=properties,
    )


def _kv_rule() -> Any:
    return importlib.import_module("scanner.rules.az_kv_006")


def _partial_inventory_client(vaults: list) -> MockAzureClient:
    client = MockAzureClient().set_key_vaults(vaults)
    client.credential = _OfflineCredential()
    return client


def test_missing_properties_is_unknown_and_never_pass(monkeypatch, tmp_path):
    client = _partial_inventory_client([_vault("kv-no-props", None)])

    result = _scan(_kv_rule(), client, monkeypatch)

    [evaluation] = result["evaluations"]
    assert evaluation["status"] == EvaluationStatus.UNKNOWN
    assert evaluation["reason_code"] == MISSING_PROPERTIES
    assert result["findings"] == []
    assert _control_status(result, "AZ-KV-006", tmp_path, monkeypatch) == EvaluationStatus.UNKNOWN


def test_partial_inventory_keeps_the_real_fail_and_does_not_hide_the_unknown(monkeypatch, tmp_path):
    client = _partial_inventory_client(
        [
            _vault("kv-policies", make_resource(enable_rbac_authorization=False)),
            _vault("kv-no-props", None),
            _vault("kv-rbac", make_resource(enable_rbac_authorization=True)),
        ]
    )

    result = _scan(_kv_rule(), client, monkeypatch)

    by_name = {e["resource_id"].rsplit("/", 1)[1]: e["status"] for e in result["evaluations"]}
    assert by_name == {
        "kv-policies": EvaluationStatus.FAIL,
        "kv-no-props": EvaluationStatus.UNKNOWN,
        "kv-rbac": EvaluationStatus.PASS,
    }
    assert [f["resource_name"] for f in result["findings"]] == ["kv-policies"]
    assert "AZ-KV-006" not in result["failed_rule_ids"]
    # FAIL outranks UNKNOWN and PASS: the compliant vault cannot outvote the bad one.
    assert _control_status(result, "AZ-KV-006", tmp_path, monkeypatch) == EvaluationStatus.FAIL


def test_partial_pass_and_unknown_never_rolls_up_to_pass(monkeypatch, tmp_path):
    client = _partial_inventory_client(
        [
            _vault("kv-no-props", None),
            _vault("kv-rbac", make_resource(enable_rbac_authorization=True)),
        ]
    )

    result = _scan(_kv_rule(), client, monkeypatch)

    assert _control_status(result, "AZ-KV-006", tmp_path, monkeypatch) == EvaluationStatus.UNKNOWN


def test_evidence_unavailable_reason_code_is_a_known_constant():
    # Per-resource lookups that return None are UNKNOWN/EVIDENCE_UNAVAILABLE.
    # Rules that perform such lookups assert it in their own tests; this
    # keeps the shared vocabulary from being renamed without updating the matrix.
    assert EVIDENCE_UNAVAILABLE == "EVIDENCE_UNAVAILABLE"


# ── Engine bookkeeping that the compliance report relies on ─────────────────


def test_failed_rule_is_forced_to_error_even_if_stale_rows_say_pass(monkeypatch, tmp_path):
    """A rule the engine recorded as failed must not report PASS or UNKNOWN."""
    client = _FaultClient(None)
    result = _scan(_kv_rule(), client, monkeypatch)
    result["evaluations"] = [
        {"rule_id": "AZ-KV-006", "status": EvaluationStatus.PASS, "resource_id": f"/subscriptions/{_SUB}"}
    ]

    assert result["failed_rule_ids"] == ["AZ-KV-006"]
    assert _control_status(result, "AZ-KV-006", tmp_path, monkeypatch) == EvaluationStatus.ERROR
