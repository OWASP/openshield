"""Contract every rule exposing evaluate() must satisfy (#369).

Rules are discovered from ``scanner/rules/az_*.py`` exactly as the engine
loads them, so each family migration is checked as soon as it adds
``evaluate()``. A migrated rule must also register a fixture in
``FIXTURES`` below: a client holding at least one compliant and one
non-compliant resource, so the PASS/FAIL and scan() parity checks have
something real to compare.
"""

import copy
import importlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict

import pytest

from scanner.evaluation import EvaluationStatus, RuleEvaluation, fail_findings
from tests.helpers.mock_azure import MockAzureClient, make_resource

_SUB = "00000000-0000-0000-0000-000000000001"
_SCOPE = f"/subscriptions/{_SUB}"
_OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
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


# ── Per-rule fixtures ───────────────────────────────────────────────────────
#
# Some rules are per-resource (a single call naturally yields both a PASS and a
# FAIL); others are subscription-singular (AZ-GOV-001/002/006: one subscription,
# one outcome) so they can only be PASS *or* FAIL in a single call. A fixture
# therefore registers two scenarios — a ``passing`` client and a ``failing``
# client — rather than one call that must produce both.


@dataclass
class ContractFixture:
    """A passing-scenario and a failing-scenario client factory for one rule."""

    passing: Callable[[], MockAzureClient]
    failing: Callable[[], MockAzureClient]


def _kv_006_client(include_fail: bool) -> MockAzureClient:
    def vault(name: str, **props: Any) -> Any:
        return make_resource(
            id=f"{_SCOPE}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/{name}",
            name=name,
            location="eastus",
            properties=make_resource(**props),
        )

    vaults = [vault("kv-rbac", enable_rbac_authorization=True)]
    if include_fail:
        vaults.append(vault("kv-policies", enable_rbac_authorization=False))
    return MockAzureClient().set_key_vaults(vaults)


# ── Governance fixtures: a crafted snapshot + the shared policy below ───────

_GOV_POLICY = {
    "approved_management_group_ids": ["/providers/microsoft.management/managementgroups/prod"],
    "required_policy_initiatives": [{"definition_id": "/definitions/base", "scope": _SCOPE}],
    "preventive_policy_definition_ids": ["/definitions/deny-public"],
    "allowed_preventive_effects": ["deny"],
    "production_resource_types": ["microsoft.storage/storageaccounts"],
    "production_tag": "environment",
    "production_tag_values": ["prod"],
    "maximum_subscription_owners": 1,
    "privileged_role_definition_ids": [_OWNER],
    "approved_privileged_scopes": [f"{_SCOPE}/resourcegroups/security"],
    "approved_provider_namespaces": ["microsoft.storage"],
    "ownership_tags": ["owner"],
    "drift_sla_days": 30,
    "excluded_resource_ids": [],
}

_PROD_RESOURCE = f"{_SCOPE}/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/data"


def _gov_client(snapshot: Dict[str, Any]) -> MockAzureClient:
    """A MockAzureClient whose governance snapshot is the crafted dict.

    The shared policy is supplied via OPENSHIELD_GOVERNANCE_POLICY by the
    autouse ``_governance_policy_env`` fixture below.
    """
    client = MockAzureClient()
    client.get_governance_snapshot = lambda _sub, _snap=snapshot: _snap
    return client


def _owner_assignment(name: str, scope: str = _SCOPE) -> Dict[str, Any]:
    return {
        "id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/{name}",
        "properties": {"roleDefinitionId": f"{scope}/providers/Microsoft.Authorization/roleDefinitions/{_OWNER}"},
    }


def _iso(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


_DENY_DEFINITION = {
    "id": "/definitions/deny-public",
    "properties": {
        "parameters": {"effect": {"defaultValue": "Deny"}},
        "policyRule": {"then": {"effect": "[parameters('effect')]"}},
    },
}
_AUDIT_DEFINITION = {
    "id": "/definitions/deny-public",
    "properties": {
        "parameters": {"effect": {"defaultValue": "Audit"}},
        "policyRule": {"then": {"effect": "[parameters('effect')]"}},
    },
}
_PREVENTIVE_ASSIGNMENT = {
    "id": f"{_SCOPE}/providers/Microsoft.Authorization/policyAssignments/deny",
    "properties": {"policyDefinitionId": "/definitions/deny-public", "parameters": {}},
}


FIXTURES: Dict[str, ContractFixture] = {
    "AZ-KV-006": ContractFixture(
        passing=lambda: _kv_006_client(include_fail=False),
        failing=lambda: _kv_006_client(include_fail=True),
    ),
    "AZ-GOV-001": ContractFixture(
        passing=lambda: _gov_client(
            {
                "hierarchy": [
                    {"managementGroupAncestorsChain": [{"id": _GOV_POLICY["approved_management_group_ids"][0]}]}
                ]
            }
        ),
        failing=lambda: _gov_client({"hierarchy": [{"managementGroupAncestorsChain": []}]}),
    ),
    "AZ-GOV-002": ContractFixture(
        passing=lambda: _gov_client(
            {
                "policy_assignments": [
                    {
                        "id": f"{_SCOPE}/providers/Microsoft.Authorization/policyAssignments/base",
                        "properties": {"policyDefinitionId": "/definitions/base"},
                    }
                ]
            }
        ),
        failing=lambda: _gov_client({"policy_assignments": []}),
    ),
    "AZ-GOV-003": ContractFixture(
        passing=lambda: _gov_client(
            {"policy_assignments": [_PREVENTIVE_ASSIGNMENT], "policy_definitions": [_DENY_DEFINITION]}
        ),
        failing=lambda: _gov_client(
            {"policy_assignments": [_PREVENTIVE_ASSIGNMENT], "policy_definitions": [_AUDIT_DEFINITION]}
        ),
    ),
    "AZ-GOV-004": ContractFixture(
        passing=lambda: _gov_client(
            {
                "policy_exemptions": [
                    {
                        "id": f"{_SCOPE}/providers/Microsoft.Authorization/policyExemptions/approved",
                        "properties": {
                            "expiresOn": _iso(20),
                            "metadata": {"owner": "team", "justification": "migration"},
                        },
                    }
                ]
            }
        ),
        failing=lambda: _gov_client({"policy_exemptions": [{"id": "exemption", "properties": {"metadata": {}}}]}),
    ),
    "AZ-GOV-005": ContractFixture(
        passing=lambda: _gov_client(
            {
                "resources": [
                    {"id": _PROD_RESOURCE, "type": "Microsoft.Storage/storageAccounts", "tags": {"Environment": "Prod"}}
                ],
                "locks": [
                    {
                        "id": f"{_SCOPE}/resourceGroups/prod/providers/Microsoft.Authorization/locks/protect",
                        "properties": {"level": "CanNotDelete"},
                    }
                ],
            }
        ),
        failing=lambda: _gov_client(
            {
                "resources": [
                    {"id": _PROD_RESOURCE, "type": "Microsoft.Storage/storageAccounts", "tags": {"Environment": "Prod"}}
                ],
                "locks": [],
            }
        ),
    ),
    "AZ-GOV-006": ContractFixture(
        passing=lambda: _gov_client({"role_assignments": [_owner_assignment("one")]}),
        failing=lambda: _gov_client({"role_assignments": [_owner_assignment("one"), _owner_assignment("two")]}),
    ),
    "AZ-GOV-007": ContractFixture(
        passing=lambda: _gov_client(
            {
                "role_assignments": [
                    {
                        "id": f"{_SCOPE}/resourceGroups/security/providers/Microsoft.Authorization/roleAssignments/ok",
                        "properties": {"roleDefinitionId": f"/roleDefinitions/{_OWNER}"},
                    }
                ]
            }
        ),
        failing=lambda: _gov_client(
            {
                "role_assignments": [
                    {
                        "id": f"{_SCOPE}/providers/Microsoft.Authorization/roleAssignments/broad",
                        "properties": {"roleDefinitionId": f"/roleDefinitions/{_OWNER}"},
                    }
                ]
            }
        ),
    ),
    "AZ-GOV-008": ContractFixture(
        passing=lambda: _gov_client(
            {"providers": [{"namespace": "Microsoft.Storage", "registrationState": "Registered"}]}
        ),
        failing=lambda: _gov_client(
            {"providers": [{"namespace": "Microsoft.Unapproved", "registrationState": "Registered"}]}
        ),
    ),
    "AZ-GOV-009": ContractFixture(
        passing=lambda: _gov_client(
            {
                "resources": [
                    {
                        "id": _PROD_RESOURCE,
                        "type": "Microsoft.Storage/storageAccounts",
                        "tags": {"environment": "prod", "owner": "payments"},
                    }
                ]
            }
        ),
        failing=lambda: _gov_client(
            {
                "resources": [
                    {"id": _PROD_RESOURCE, "type": "Microsoft.Storage/storageAccounts", "tags": {"environment": "prod"}}
                ]
            }
        ),
    ),
    "AZ-GOV-010": ContractFixture(
        passing=lambda: _gov_client(
            {
                "policy_states": [
                    {"complianceState": "NonCompliant", "timestamp": _iso(-29), "resourceId": _PROD_RESOURCE}
                ]
            }
        ),
        failing=lambda: _gov_client(
            {
                "policy_states": [
                    {"complianceState": "NonCompliant", "timestamp": _iso(-31), "resourceId": _PROD_RESOURCE}
                ]
            }
        ),
    ),
}


@pytest.fixture(autouse=True)
def _governance_policy_env(tmp_path, monkeypatch):
    """Point OPENSHIELD_GOVERNANCE_POLICY at the shared policy so governance
    fixtures resolve a real policy. Harmless for non-governance rules."""
    policy_file = tmp_path / "governance_policy.json"
    policy_file.write_text(json.dumps(_GOV_POLICY), encoding="utf-8")
    monkeypatch.setenv("OPENSHIELD_GOVERNANCE_POLICY", str(policy_file))


def _ids(module: Any) -> str:
    return module.RULE_ID


_WITH_FIXTURE = [r for r in MIGRATED if r.RULE_ID in FIXTURES]


def _stable(findings: Any) -> Any:
    """Drop the volatile ``evidence_collected_at`` collection timestamp so a
    scan() and a separate evaluate() of the same rule compare for equality."""
    out = copy.deepcopy(findings)
    for item in out:
        metadata = item.get("metadata")
        if isinstance(metadata, dict):
            metadata.pop("evidence_collected_at", None)
    return out


def _assert_well_formed(rule: Any, evaluations: Any) -> None:
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


@pytest.mark.parametrize("rule", _WITH_FIXTURE, ids=_ids)
def test_failing_fixture_produces_a_fail_carrying_the_rule_finding(rule):
    evaluations = rule.evaluate(FIXTURES[rule.RULE_ID].failing(), _SUB)

    assert any(e.status == EvaluationStatus.FAIL for e in evaluations), (
        f"{rule.RULE_ID} failing fixture produced no FAIL"
    )
    _assert_well_formed(rule, evaluations)


@pytest.mark.parametrize("rule", _WITH_FIXTURE, ids=_ids)
def test_passing_fixture_produces_a_pass_and_no_fail(rule):
    evaluations = rule.evaluate(FIXTURES[rule.RULE_ID].passing(), _SUB)

    statuses = {e.status for e in evaluations}
    assert EvaluationStatus.PASS in statuses, f"{rule.RULE_ID} passing fixture produced no PASS"
    assert EvaluationStatus.FAIL not in statuses, f"{rule.RULE_ID} passing fixture unexpectedly produced a FAIL"
    _assert_well_formed(rule, evaluations)


@pytest.mark.parametrize("rule", _WITH_FIXTURE, ids=_ids)
def test_scan_returns_exactly_the_fail_findings(rule):
    for factory in (FIXTURES[rule.RULE_ID].passing, FIXTURES[rule.RULE_ID].failing):
        client = factory()
        expected = fail_findings(rule.evaluate(client, _SUB))
        actual = rule.scan(client, _SUB)
        assert _stable(actual) == _stable(expected)
