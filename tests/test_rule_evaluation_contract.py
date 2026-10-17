"""Contract every rule exposing evaluate() must satisfy (#369).

Rules are discovered from ``scanner/rules/az_*.py`` exactly as the engine
loads them, so each family migration is checked as soon as it adds
``evaluate()``. A migrated rule must also register a fixture in
``FIXTURES`` below: a client holding at least one compliant and one
non-compliant resource, so the PASS/FAIL and scan() parity checks have
something real to compare.
"""

import importlib
from pathlib import Path
from typing import Any, Callable, Dict

import pytest

from scanner.evaluation import EvaluationStatus, RuleEvaluation, fail_findings
from tests.helpers.mock_azure import MockAzureClient, make_resource

_SUB = "00000000-0000-0000-0000-000000000001"
_RULES_DIR = Path(__file__).resolve().parent.parent / "scanner" / "rules"


def _migrated_rules():
    modules = []
    for path in sorted(_RULES_DIR.glob("az_*.py")):
        module = importlib.import_module(f"scanner.rules.{path.stem}")
        if callable(getattr(module, "evaluate", None)):
            modules.append(module)
    return modules


MIGRATED = _migrated_rules()


class _UniformInventoryClient(MockAzureClient):
    """Every inventory and lookup call returns the same value.

    ``None`` simulates Azure failing every call; ``[]`` simulates a
    subscription that has none of anything.
    """

    def __init__(self, value: Any) -> None:
        super().__init__()
        self._value = value

    def __getattribute__(self, name: str) -> Any:
        if name.startswith(("list_", "get_")):
            value = object.__getattribute__(self, "_value")
            return lambda *args, **kwargs: value
        return object.__getattribute__(self, name)


# ── Per-rule fixtures: at least one PASS and one FAIL ───────────────────────


def _kv_006_fixture() -> MockAzureClient:
    def vault(name: str, **props: Any) -> Any:
        return make_resource(
            id=f"/subscriptions/{_SUB}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/{name}",
            name=name,
            location="eastus",
            properties=make_resource(**props),
        )

    return MockAzureClient().set_key_vaults(
        [vault("kv-rbac", enable_rbac_authorization=True), vault("kv-policies", enable_rbac_authorization=False)]
    )


FIXTURES: Dict[str, Callable[[], MockAzureClient]] = {
    "AZ-KV-006": _kv_006_fixture,
}


def _ids(module: Any) -> str:
    return module.RULE_ID


def test_at_least_one_rule_is_migrated():
    assert MIGRATED, "no rule exposes evaluate(); the contract tests below would silently check nothing"


@pytest.mark.parametrize("rule", MIGRATED, ids=_ids)
def test_failed_inventory_is_error_never_pass_or_not_applicable(rule):
    evaluations = rule.evaluate(_UniformInventoryClient(None), _SUB)

    assert evaluations, f"{rule.RULE_ID} reported no coverage when Azure failed"
    statuses = {e.status for e in evaluations}
    assert EvaluationStatus.ERROR in statuses
    assert EvaluationStatus.PASS not in statuses
    assert EvaluationStatus.NOT_APPLICABLE not in statuses


@pytest.mark.parametrize("rule", MIGRATED, ids=_ids)
def test_empty_inventory_is_not_applicable(rule):
    evaluations = rule.evaluate(_UniformInventoryClient([]), _SUB)

    assert evaluations, f"{rule.RULE_ID} reported no coverage for an empty subscription"
    assert {e.status for e in evaluations} == {EvaluationStatus.NOT_APPLICABLE}


@pytest.mark.parametrize("rule", MIGRATED, ids=_ids)
def test_rule_registers_a_contract_fixture(rule):
    assert rule.RULE_ID in FIXTURES, f"add a {rule.RULE_ID} fixture to FIXTURES in {Path(__file__).name}"


@pytest.mark.parametrize("rule", [r for r in MIGRATED if r.RULE_ID in FIXTURES], ids=_ids)
def test_evaluations_are_well_formed_and_fail_carries_the_rule_finding(rule):
    evaluations = rule.evaluate(FIXTURES[rule.RULE_ID](), _SUB)

    statuses = {e.status for e in evaluations}
    assert {EvaluationStatus.PASS, EvaluationStatus.FAIL} <= statuses, "fixture must produce a PASS and a FAIL"
    for evaluation in evaluations:
        assert isinstance(evaluation, RuleEvaluation)
        assert evaluation.rule_id == rule.RULE_ID
        if evaluation.status == EvaluationStatus.FAIL:
            finding = evaluation.finding
            assert finding, f"{rule.RULE_ID} FAIL for {evaluation.resource_id} has no finding"
            assert finding["rule_id"] == rule.RULE_ID
            assert finding["resource_id"] == evaluation.resource_id
            assert finding["severity"] == rule.SEVERITY
            assert finding["frameworks"] == rule.FRAMEWORKS
        else:
            assert evaluation.finding is None


@pytest.mark.parametrize("rule", [r for r in MIGRATED if r.RULE_ID in FIXTURES], ids=_ids)
def test_scan_returns_exactly_the_fail_findings(rule):
    client = FIXTURES[rule.RULE_ID]()

    assert rule.scan(client, _SUB) == fail_findings(rule.evaluate(client, _SUB))
