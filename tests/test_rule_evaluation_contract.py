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
from types import SimpleNamespace
from typing import Any, Callable, Dict

import pytest

from scanner.evaluation import EvaluationStatus, RuleEvaluation, fail_findings
from tests.helpers.mock_azure import MockAzureClient, make_resource
from tests.helpers.security_operations import (
    DEFAULT_POLICY_PAYLOAD,
    diagnostic_setting,
    log_setting,
    make_collector,
    retention_policy,
    workspace,
    write_policy,
)

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


# ── Security-operations fixtures (AZ-SECOPS-*) ─────────────────────────────
#
# The collector is reached through ``get_security_operations_collector`` on
# the client, exactly like AzureClient; the policy comes from
# DEFAULT_POLICY_PAYLOAD via the autouse ``_security_operations_policy_env``
# fixture below.

_SECOPS_APPROVED = DEFAULT_POLICY_PAYLOAD["approved_destination_ids"][0]
_CRITICAL_ID = f"{_SCOPE}/resourceGroups/app/providers/Microsoft.KeyVault/vaults/kv1"


def _secops_client(**collector_doubles: Any) -> MockAzureClient:
    collector = make_collector(**collector_doubles)
    client = MockAzureClient()
    client.get_security_operations_collector = lambda _sub, _collector=collector: _collector
    return client


def _subscription_settings(*settings: Any) -> SimpleNamespace:
    return SimpleNamespace(subscription_diagnostic_settings=SimpleNamespace(list=lambda: list(settings)))


def _critical_client(*settings: Any) -> MockAzureClient:
    """One critical Key Vault whose diagnostic settings are ``settings``."""
    return _secops_client(
        resource_inventory=lambda: [SimpleNamespace(id=_CRITICAL_ID, type="Microsoft.KeyVault/vaults")],
        monitor_client=SimpleNamespace(diagnostic_settings=SimpleNamespace(list=lambda _rid: list(settings))),
    )


def _all_categories() -> list:
    return [log_setting(category=c) for c in DEFAULT_POLICY_PAYLOAD["required_activity_categories"]]


def _defender_client(storage_tier: str) -> MockAzureClient:
    pricings = [
        SimpleNamespace(name="VirtualMachines", pricing_tier="Standard"),
        SimpleNamespace(name="StorageAccounts", pricing_tier=storage_tier),
    ]
    security = SimpleNamespace(pricings=SimpleNamespace(list=lambda _scope: SimpleNamespace(value=pricings)))
    return _secops_client(security_client=security)


def _assessment_client(age_days: int) -> MockAzureClient:
    first_seen = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat()
    assessment = SimpleNamespace(
        id=f"{_SCOPE}/providers/Microsoft.Security/assessments/a1",
        name="a1",
        metadata=SimpleNamespace(display_name="Recommendation a1", severity="High"),
        status=SimpleNamespace(code="Unhealthy"),
        additional_data={"firstEvaluationDate": first_seen},
        resource_details=SimpleNamespace(
            id=f"{_SCOPE}/resourceGroups/app/providers/Microsoft.Compute/virtualMachines/vm1"
        ),
    )
    security = SimpleNamespace(assessments=SimpleNamespace(list=lambda _scope: [assessment]))
    return _secops_client(security_client=security)


def _sentinel_client(connectors: list = (), alert_rules: list = ()) -> MockAzureClient:
    sentinel = SimpleNamespace(
        sentinel_onboarding_states=SimpleNamespace(list=lambda _rg, _wn: SimpleNamespace(value=[SimpleNamespace()])),
        data_connectors=SimpleNamespace(list=lambda _rg, _wn: list(connectors)),
        alert_rules=SimpleNamespace(list=lambda _rg, _wn: list(alert_rules)),
        automation_rules=SimpleNamespace(list=lambda _rg, _wn: []),
    )
    return _secops_client(
        log_analytics_client=SimpleNamespace(workspaces=SimpleNamespace(list=lambda: [workspace(name="ws1")])),
        sentinel_client_factory=lambda _rg: sentinel,
    )


def _incident_response_client(monitored: bool) -> MockAzureClient:
    group = SimpleNamespace(enabled=True, email_receivers=[SimpleNamespace()] if monitored else [])
    return _secops_client(
        monitor_client=SimpleNamespace(action_groups=SimpleNamespace(list_by_subscription_id=lambda: [group])),
        log_analytics_client=SimpleNamespace(workspaces=SimpleNamespace(list=lambda: [])),
    )


# ── Supply-chain fixtures (AZ-SC-*) ─────────────────────────────────────────


def _registry_client(include_fail: bool) -> MockAzureClient:
    """A registry passing AZ-SC-001..004, plus one failing all four when ``include_fail``."""

    def registry(name: str, ok: bool) -> Any:
        status = "enabled" if ok else "disabled"
        return make_resource(
            id=f"{_SCOPE}/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/{name}",
            name=name,
            sku=make_resource(tier="Premium"),
            properties=make_resource(
                admin_user_enabled=not ok,
                public_network_access="Disabled" if ok else "Enabled",
                anonymous_pull_enabled=not ok,
                policies=make_resource(
                    retention_policy=make_resource(status=status),
                    quarantine_policy=make_resource(status=status),
                ),
            ),
        )

    registries = [registry("acrgood", True)]
    if include_fail:
        registries.append(registry("acrbad", False))
    return MockAzureClient().set_container_registries(registries)


def _tfstate_client(include_fail: bool) -> MockAzureClient:
    """A Terraform state account passing AZ-SC-005/006, plus a failing one when ``include_fail``."""
    client = MockAzureClient()
    accounts = []
    for name, ok in (("tfgood", True), ("tfbad", False)):
        if not ok and not include_fail:
            continue
        accounts.append(
            make_resource(
                id=f"{_SCOPE}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/{name}", name=name
            )
        )
        container = make_resource(
            name="tfstate", container_properties=make_resource(public_access="None" if ok else "Container")
        )
        client.set_blob_containers("rg", name, [container])
        client.set_blob_service_properties(
            "rg", name, make_resource(is_versioning_enabled=ok, delete_retention_policy=None)
        )
    client.set_storage_accounts(accounts)
    return client


class _DevOps:
    def __init__(self, endpoints: list) -> None:
        self._endpoints = endpoints

    def get_service_endpoints(self) -> list:
        return self._endpoints


def _devops_client(include_fail: bool) -> MockAzureClient:
    """A service connection passing AZ-SC-007/008, plus a failing one when ``include_fail``."""

    def endpoint(name: str, ok: bool) -> Any:
        return SimpleNamespace(
            id=f"endpoint-{name}",
            name=name,
            type="AzureRM",
            is_shared=False,
            data={"scopeLevel": "ResourceGroup" if ok else "Subscription", "subscriptionId": _SUB},
            authorization=SimpleNamespace(scheme="WorkloadIdentityFederation" if ok else "ServicePrincipal"),
        )

    endpoints = [endpoint("good", True)]
    if include_fail:
        endpoints.append(endpoint("bad", False))
    client = MockAzureClient()
    client.devops_client = _DevOps(endpoints)
    return client


_SECOPS_FIXTURES: Dict[str, ContractFixture] = {
    "AZ-SECOPS-001": ContractFixture(
        passing=lambda: _secops_client(
            monitor_client=_subscription_settings(diagnostic_setting(workspace_id=_SECOPS_APPROVED))
        ),
        failing=lambda: _secops_client(monitor_client=_subscription_settings()),
    ),
    "AZ-SECOPS-002": ContractFixture(
        passing=lambda: _secops_client(
            monitor_client=_subscription_settings(
                diagnostic_setting(workspace_id=_SECOPS_APPROVED, logs=_all_categories())
            )
        ),
        failing=lambda: _secops_client(
            monitor_client=_subscription_settings(
                diagnostic_setting(workspace_id=_SECOPS_APPROVED, logs=[log_setting(category="Administrative")])
            )
        ),
    ),
    "AZ-SECOPS-003": ContractFixture(
        passing=lambda: _critical_client(diagnostic_setting(workspace_id=_SECOPS_APPROVED)),
        failing=lambda: _critical_client(),
    ),
    "AZ-SECOPS-004": ContractFixture(
        passing=lambda: _critical_client(
            diagnostic_setting(
                storage_account_id=f"{_SCOPE}/resourceGroups/sec/providers/Microsoft.Storage/storageAccounts/logs",
                logs=[log_setting(category="AuditEvent", retention_policy=retention_policy(enabled=True, days=120))],
            )
        ),
        failing=lambda: _critical_client(
            diagnostic_setting(
                storage_account_id=f"{_SCOPE}/resourceGroups/sec/providers/Microsoft.Storage/storageAccounts/logs",
                logs=[log_setting(category="AuditEvent", retention_policy=retention_policy(enabled=True, days=30))],
            )
        ),
    ),
    "AZ-SECOPS-005": ContractFixture(
        passing=lambda: _critical_client(diagnostic_setting(workspace_id=_SECOPS_APPROVED)),
        failing=lambda: _critical_client(
            diagnostic_setting(
                workspace_id=f"{_SCOPE}/resourceGroups/app/providers/Microsoft.OperationalInsights/workspaces/app-logs"
            )
        ),
    ),
    "AZ-SECOPS-006": ContractFixture(
        passing=lambda: _defender_client("Standard"),
        failing=lambda: _defender_client("Free"),
    ),
    "AZ-SECOPS-007": ContractFixture(
        passing=lambda: _assessment_client(age_days=5),
        failing=lambda: _assessment_client(age_days=45),
    ),
    "AZ-SECOPS-008": ContractFixture(
        passing=lambda: _sentinel_client(
            connectors=[
                SimpleNamespace(kind="AzureActiveDirectory", data_types=None),
                SimpleNamespace(kind="AzureSecurityCenter", data_types=None),
            ]
        ),
        failing=lambda: _sentinel_client(connectors=[SimpleNamespace(kind="AzureActiveDirectory", data_types=None)]),
    ),
    "AZ-SECOPS-009": ContractFixture(
        passing=lambda: _sentinel_client(
            alert_rules=[
                SimpleNamespace(display_name="Privileged role change", severity="High", enabled=True),
                SimpleNamespace(display_name="Credential abuse", severity="High", enabled=True),
            ]
        ),
        failing=lambda: _sentinel_client(
            alert_rules=[SimpleNamespace(display_name="Privileged role change", severity="High", enabled=True)]
        ),
    ),
    "AZ-SECOPS-010": ContractFixture(
        passing=lambda: _incident_response_client(monitored=True),
        failing=lambda: _incident_response_client(monitored=False),
    ),
}

_SUPPLY_CHAIN_FIXTURES: Dict[str, ContractFixture] = {
    **{
        f"AZ-SC-{n:03d}": ContractFixture(
            passing=lambda: _registry_client(include_fail=False),
            failing=lambda: _registry_client(include_fail=True),
        )
        for n in range(1, 5)
    },
    **{
        f"AZ-SC-{n:03d}": ContractFixture(
            passing=lambda: _tfstate_client(include_fail=False),
            failing=lambda: _tfstate_client(include_fail=True),
        )
        for n in (5, 6)
    },
    **{
        f"AZ-SC-{n:03d}": ContractFixture(
            passing=lambda: _devops_client(include_fail=False),
            failing=lambda: _devops_client(include_fail=True),
        )
        for n in (7, 8)
    },
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
    **_SECOPS_FIXTURES,
    **_SUPPLY_CHAIN_FIXTURES,
}


@pytest.fixture(autouse=True)
def _security_operations_policy_env(tmp_path, monkeypatch):
    """Point OPENSHIELD_SECURITY_OPERATIONS_POLICY at DEFAULT_POLICY_PAYLOAD so
    the AZ-SECOPS fixtures have an approved policy to judge against."""
    monkeypatch.setenv("OPENSHIELD_SECURITY_OPERATIONS_POLICY", str(write_policy(tmp_path)))


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
