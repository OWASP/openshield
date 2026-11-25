"""evaluate() status paths for AZ-SECOPS-001..010 and AZ-SC-001..008 (#375).

``tests/test_rule_evaluation_contract.py`` covers each rule's PASS, FAIL,
failed-inventory ERROR and empty-inventory NOT_APPLICABLE paths and scan()
parity. These tests cover the rest: an unconfigured policy or integration,
subscription-wide collection failures, per-scope UNKNOWN, approved
exclusions, rules with nothing in scope, and one evaluation per resource.
"""

import importlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, List

import pytest

import scanner.engine as engine_mod
from scanner.engine import ScanEngine
from scanner.evaluation import (
    APPROVED_EXCEPTION,
    EVIDENCE_UNAVAILABLE,
    INTEGRATION_NOT_CONFIGURED,
    INVENTORY_UNAVAILABLE,
    MISSING_PROPERTIES,
    NO_RESOURCES_FOUND,
    POLICY_NOT_CONFIGURED,
    POLICY_NOT_REQUIRED,
    EvaluationStatus,
    RuleEvaluation,
)
from tests.helpers.mock_azure import MockAzureClient, make_resource
from tests.helpers.security_operations import (
    DEFAULT_POLICY_PAYLOAD,
    diagnostic_setting,
    log_setting,
    make_collector,
    set_policy_env,
    workspace,
)

_SUB = "00000000-0000-0000-0000-000000000001"
_SCOPE = f"/subscriptions/{_SUB}"
_APPROVED = DEFAULT_POLICY_PAYLOAD["approved_destination_ids"][0]
_KV = f"{_SCOPE}/resourceGroups/app/providers/Microsoft.KeyVault/vaults/kv1"
_SQL = f"{_SCOPE}/resourceGroups/app/providers/Microsoft.Sql/servers/sql1"

SECOPS_RULES = [f"az_secops_{n:03d}" for n in range(1, 11)]


def _rule(name: str) -> Any:
    return importlib.import_module(f"scanner.rules.{name}")


def _statuses(evaluations: List[RuleEvaluation]) -> set:
    return {(e.status, e.reason_code) for e in evaluations}


def _secops_client(**collector_doubles: Any) -> MockAzureClient:
    collector = make_collector(**collector_doubles)
    client = MockAzureClient()
    client.get_security_operations_collector = lambda _sub: collector
    return client


def _raise(*_args: Any, **_kwargs: Any) -> Any:
    raise PermissionError("AuthorizationFailed")


def _sentinel(onboarded: bool = True, fail_connectors: bool = False, fail_rules: bool = False) -> SimpleNamespace:
    def connectors(_rg: str, _wn: str) -> list:
        if fail_connectors:
            raise PermissionError("denied")
        return []

    def alert_rules(_rg: str, _wn: str) -> list:
        if fail_rules:
            raise PermissionError("denied")
        return []

    return SimpleNamespace(
        sentinel_onboarding_states=SimpleNamespace(
            list=lambda _rg, _wn: SimpleNamespace(value=[SimpleNamespace()] if onboarded else [])
        ),
        data_connectors=SimpleNamespace(list=connectors),
        alert_rules=SimpleNamespace(list=alert_rules),
        automation_rules=SimpleNamespace(list=lambda _rg, _wn: []),
    )


def _log_analytics(*workspaces: Any) -> SimpleNamespace:
    return SimpleNamespace(workspaces=SimpleNamespace(list=lambda: list(workspaces)))


# ── Security operations: policy and collector ───────────────────────────────


@pytest.mark.parametrize("name", SECOPS_RULES)
def test_secops_unconfigured_policy_is_unknown_not_error(name, monkeypatch):
    monkeypatch.delenv("OPENSHIELD_SECURITY_OPERATIONS_POLICY", raising=False)

    evaluations = _rule(name).evaluate(_secops_client(), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.UNKNOWN, POLICY_NOT_CONFIGURED)}
    assert [e.resource_id for e in evaluations] == [_SCOPE]


@pytest.mark.parametrize("name", SECOPS_RULES)
def test_secops_invalid_policy_file_is_unknown(name, monkeypatch, tmp_path):
    bad = tmp_path / "policy.json"
    bad.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("OPENSHIELD_SECURITY_OPERATIONS_POLICY", str(bad))

    evaluations = _rule(name).evaluate(_secops_client(), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.UNKNOWN, POLICY_NOT_CONFIGURED)}


@pytest.mark.parametrize("name", SECOPS_RULES)
def test_secops_collector_that_cannot_be_built_is_error(name, monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    client = MockAzureClient()
    client.get_security_operations_collector = lambda _sub: None

    evaluations = _rule(name).evaluate(client, _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.ERROR, INVENTORY_UNAVAILABLE)}


_FAILED_COLLECTIONS = {
    "az_secops_001": dict(
        monitor_client=SimpleNamespace(subscription_diagnostic_settings=SimpleNamespace(list=_raise))
    ),
    "az_secops_002": dict(
        monitor_client=SimpleNamespace(subscription_diagnostic_settings=SimpleNamespace(list=_raise))
    ),
    "az_secops_003": dict(resource_inventory=_raise),
    "az_secops_004": dict(resource_inventory=_raise),
    "az_secops_005": dict(resource_inventory=_raise),
    "az_secops_006": dict(security_client=SimpleNamespace(pricings=SimpleNamespace(list=_raise))),
    "az_secops_007": dict(security_client=SimpleNamespace(assessments=SimpleNamespace(list=_raise))),
    "az_secops_008": dict(log_analytics_client=SimpleNamespace(workspaces=SimpleNamespace(list=_raise))),
    "az_secops_009": dict(log_analytics_client=SimpleNamespace(workspaces=SimpleNamespace(list=_raise))),
    "az_secops_010": dict(
        monitor_client=SimpleNamespace(action_groups=SimpleNamespace(list_by_subscription_id=_raise))
    ),
}


@pytest.mark.parametrize("name", sorted(_FAILED_COLLECTIONS))
def test_secops_failed_subscription_collection_is_error_never_pass(name, monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)

    evaluations = _rule(name).evaluate(_secops_client(**_FAILED_COLLECTIONS[name]), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.ERROR, INVENTORY_UNAVAILABLE)}
    assert all(e.finding is None for e in evaluations)


@pytest.mark.parametrize("name", ["az_secops_001", "az_secops_002", "az_secops_006"])
def test_secops_scan_still_returns_no_findings_when_the_collection_fails(name, monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)

    assert _rule(name).scan(_secops_client(**_FAILED_COLLECTIONS[name]), _SUB) == []


# ── Security operations: rules with nothing to judge ────────────────────────


def test_secops_002_without_an_approved_export_is_not_applicable(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    monitor = SimpleNamespace(
        subscription_diagnostic_settings=SimpleNamespace(
            list=lambda: [diagnostic_setting(workspace_id="/x/unapproved", logs=[log_setting(category="Security")])]
        )
    )

    evaluations = _rule("az_secops_002").evaluate(_secops_client(monitor_client=monitor), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.NOT_APPLICABLE, NO_RESOURCES_FOUND)}


@pytest.mark.parametrize(
    "name, override",
    [
        ("az_secops_002", {"required_activity_categories": []}),
        ("az_secops_006", {"required_defender_plans": []}),
        ("az_secops_008", {"required_sentinel_connectors": []}),
        ("az_secops_009", {"required_high_severity_analytics": []}),
    ],
)
def test_secops_nothing_required_by_policy_is_not_applicable(name, override, monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, **override)

    evaluations = _rule(name).evaluate(_secops_client(), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.NOT_APPLICABLE, POLICY_NOT_REQUIRED)}


@pytest.mark.parametrize("name", ["az_secops_003", "az_secops_004", "az_secops_005"])
def test_secops_no_critical_resources_is_not_applicable(name, monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)

    evaluations = _rule(name).evaluate(_secops_client(resource_inventory=lambda: []), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.NOT_APPLICABLE, NO_RESOURCES_FOUND)}


def _critical(*settings: Any, fail_diagnostics: bool = False) -> MockAzureClient:
    def diagnostics(_resource_id: str) -> list:
        if fail_diagnostics:
            raise PermissionError("denied")
        return list(settings)

    return _secops_client(
        resource_inventory=lambda: [
            SimpleNamespace(id=_KV, type="Microsoft.KeyVault/vaults"),
            SimpleNamespace(id=_SQL, type="Microsoft.Sql/servers"),
        ],
        monitor_client=SimpleNamespace(diagnostic_settings=SimpleNamespace(list=diagnostics)),
    )


@pytest.mark.parametrize(
    "name, judged",
    [
        ("az_secops_003", (EvaluationStatus.PASS, None)),
        # An approved Log Analytics export has no Storage retention to check.
        ("az_secops_004", (EvaluationStatus.NOT_APPLICABLE, NO_RESOURCES_FOUND)),
        ("az_secops_005", (EvaluationStatus.PASS, None)),
    ],
)
def test_secops_approved_exclusion_is_not_applicable_and_the_rest_is_judged(name, judged, monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, approved_exclusions=[_KV])

    evaluations = _rule(name).evaluate(_critical(diagnostic_setting(workspace_id=_APPROVED)), _SUB)

    by_id = {e.resource_id: (e.status, e.reason_code) for e in evaluations}
    assert by_id == {_KV: (EvaluationStatus.NOT_APPLICABLE, APPROVED_EXCEPTION), _SQL: judged}


@pytest.mark.parametrize("name", ["az_secops_003", "az_secops_004", "az_secops_005"])
def test_secops_unreadable_diagnostic_settings_are_unknown_per_resource(name, monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)

    evaluations = _rule(name).evaluate(_critical(fail_diagnostics=True), _SUB)

    assert {e.resource_id for e in evaluations} == {_KV, _SQL}
    assert _statuses(evaluations) == {(EvaluationStatus.UNKNOWN, EVIDENCE_UNAVAILABLE)}


def test_secops_004_without_a_storage_export_is_not_applicable(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)

    evaluations = _rule("az_secops_004").evaluate(_critical(diagnostic_setting(workspace_id=_APPROVED)), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.NOT_APPLICABLE, NO_RESOURCES_FOUND)}


def test_secops_005_without_any_export_is_not_applicable(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)

    evaluations = _rule("az_secops_005").evaluate(_critical(), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.NOT_APPLICABLE, NO_RESOURCES_FOUND)}


# ── AZ-SECOPS-007: one evaluation per affected resource ─────────────────────


def _assessment(name: str, age_days: Any, resource_id: str = f"{_SCOPE}/resourceGroups/app/vm1") -> SimpleNamespace:
    additional = {}
    if age_days is not None:
        additional["firstEvaluationDate"] = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat()
    return SimpleNamespace(
        id=f"{_SCOPE}/providers/Microsoft.Security/assessments/{name}",
        name=name,
        metadata=SimpleNamespace(display_name=f"Recommendation {name}", severity="High"),
        status=SimpleNamespace(code="Unhealthy"),
        additional_data=additional,
        resource_details=SimpleNamespace(id=resource_id),
    )


def _assessments(*items: Any) -> MockAzureClient:
    return _secops_client(security_client=SimpleNamespace(assessments=SimpleNamespace(list=lambda _scope: list(items))))


def test_secops_007_two_overdue_recommendations_on_one_resource_give_one_fail(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, defender_recommendation_sla_days=30)

    evaluations = _rule("az_secops_007").evaluate(_assessments(_assessment("a", 40), _assessment("b", 90)), _SUB)

    [evaluation] = evaluations
    assert evaluation.status == EvaluationStatus.FAIL
    assert evaluation.finding["resource_name"] == "Recommendation b"
    assert evaluation.finding["metadata"]["age_days"] == 90
    assert [r["name"] for r in evaluation.finding["metadata"]["overdue_recommendations"]] == [
        "Recommendation a",
        "Recommendation b",
    ]


def test_secops_007_undated_recommendation_is_unknown(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)

    evaluations = _rule("az_secops_007").evaluate(_assessments(_assessment("a", None)), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.UNKNOWN, MISSING_PROPERTIES)}


def test_secops_007_no_unresolved_recommendation_is_a_subscription_pass(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)

    evaluations = _rule("az_secops_007").evaluate(_assessments(), _SUB)

    assert [(e.resource_id, e.status) for e in evaluations] == [(_SCOPE, EvaluationStatus.PASS)]


def test_secops_007_recommendation_without_any_id_is_unknown_not_an_empty_finding(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    unidentified = _assessment("a", 90, resource_id="")
    unidentified.id = ""

    evaluations = _rule("az_secops_007").evaluate(_assessments(unidentified), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.UNKNOWN, MISSING_PROPERTIES)}
    assert all(e.resource_id for e in evaluations)


# ── AZ-SECOPS-008/009/010: Sentinel scopes ──────────────────────────────────


@pytest.mark.parametrize("name", ["az_secops_008", "az_secops_009"])
def test_secops_no_onboarded_workspace_is_not_applicable(name, monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    client = _secops_client(
        log_analytics_client=_log_analytics(workspace(name="ws1")),
        sentinel_client_factory=lambda _rg: _sentinel(onboarded=False),
    )

    evaluations = _rule(name).evaluate(client, _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.NOT_APPLICABLE, NO_RESOURCES_FOUND)}


@pytest.mark.parametrize("name, failure", [("az_secops_008", "fail_connectors"), ("az_secops_009", "fail_rules")])
def test_secops_unreadable_workspace_detail_is_unknown_for_that_workspace(name, failure, monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    client = _secops_client(
        log_analytics_client=_log_analytics(workspace(name="ws1")),
        sentinel_client_factory=lambda _rg: _sentinel(**{failure: True}),
    )

    evaluations = _rule(name).evaluate(client, _SUB)

    assert evaluations
    assert _statuses(evaluations) == {(EvaluationStatus.UNKNOWN, EVIDENCE_UNAVAILABLE)}
    assert all("/workspaces/ws1/providers/Microsoft.SecurityInsights/" in e.resource_id for e in evaluations)


def test_secops_008_workspace_whose_onboarding_cannot_be_checked_is_unknown(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, required_sentinel_connectors=["AzureActiveDirectory"])
    healthy = _sentinel()
    healthy.data_connectors = SimpleNamespace(
        list=lambda _rg, _wn: [SimpleNamespace(kind="AzureActiveDirectory", data_types=None)]
    )

    def factory(resource_group: str) -> SimpleNamespace:
        if resource_group == "rg-broken":
            return SimpleNamespace(sentinel_onboarding_states=SimpleNamespace(list=_raise))
        return healthy

    client = _secops_client(
        log_analytics_client=_log_analytics(workspace(name="ws1"), workspace(name="ws2", resource_group="rg-broken")),
        sentinel_client_factory=factory,
    )

    evaluations = _rule("az_secops_008").evaluate(client, _SUB)

    statuses = {e.resource_id.split("/workspaces/")[1].split("/")[0]: e.status for e in evaluations}
    assert statuses == {"ws1": EvaluationStatus.PASS, "ws2": EvaluationStatus.UNKNOWN}


def test_secops_010_unreadable_sentinel_without_an_action_group_is_unknown(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    client = _secops_client(
        monitor_client=SimpleNamespace(action_groups=SimpleNamespace(list_by_subscription_id=lambda: [])),
        log_analytics_client=SimpleNamespace(workspaces=SimpleNamespace(list=_raise)),
    )

    evaluations = _rule("az_secops_010").evaluate(client, _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.UNKNOWN, EVIDENCE_UNAVAILABLE)}


# ── Supply chain: container registries ──────────────────────────────────────


def _registry(**props: Any) -> Any:
    return make_resource(
        id=f"{_SCOPE}/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/acr1",
        name="acr1",
        sku=make_resource(tier="Standard"),
        properties=make_resource(**props),
    )


@pytest.mark.parametrize(
    "name, field",
    [
        ("az_sc_001", "admin_user_enabled"),
        ("az_sc_002", "public_network_access"),
        ("az_sc_003", "anonymous_pull_enabled"),
    ],
)
def test_sc_registry_field_not_reported_is_unknown(name, field):
    client = MockAzureClient().set_container_registries([_registry(**{field: None})])

    evaluations = _rule(name).evaluate(client, _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.UNKNOWN, MISSING_PROPERTIES)}
    assert _rule(name).scan(client, _SUB) == []


@pytest.mark.parametrize("name", ["az_sc_001", "az_sc_002", "az_sc_003", "az_sc_004"])
def test_sc_registry_without_properties_is_unknown(name):
    registry = make_resource(
        id=f"{_SCOPE}/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/acr1",
        name="acr1",
        properties=None,
    )

    evaluations = _rule(name).evaluate(MockAzureClient().set_container_registries([registry]), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.UNKNOWN, MISSING_PROPERTIES)}


@pytest.mark.parametrize("name", ["az_sc_001", "az_sc_002", "az_sc_003", "az_sc_004"])
def test_sc_registry_without_an_id_is_unknown_not_an_empty_finding(name):
    registry = make_resource(id="", name="acr1", properties=make_resource(admin_user_enabled=True))

    evaluations = _rule(name).evaluate(MockAzureClient().set_container_registries([registry]), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.UNKNOWN, MISSING_PROPERTIES)}
    assert all(e.resource_id for e in evaluations)


def test_sc_004_standard_registry_with_retention_passes_without_quarantine():
    registry = _registry(
        policies=make_resource(retention_policy=make_resource(status="enabled"), quarantine_policy=None)
    )

    evaluations = _rule("az_sc_004").evaluate(MockAzureClient().set_container_registries([registry]), _SUB)

    assert [e.status for e in evaluations] == [EvaluationStatus.PASS]


# ── Supply chain: Terraform state storage ───────────────────────────────────


def _state_account(containers: Any, blob_service: Any = None) -> MockAzureClient:
    client = MockAzureClient().set_storage_accounts(
        [make_resource(id=f"{_SCOPE}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1", name="sa1")]
    )
    client.set_blob_containers("rg", "sa1", containers)
    client.set_blob_service_properties("rg", "sa1", blob_service)
    return client


@pytest.mark.parametrize("name", ["az_sc_005", "az_sc_006"])
def test_sc_container_listing_failure_is_unknown_for_that_account(name):
    evaluations = _rule(name).evaluate(_state_account(None), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.UNKNOWN, EVIDENCE_UNAVAILABLE)}


@pytest.mark.parametrize("name", ["az_sc_005", "az_sc_006"])
def test_sc_account_without_state_container_is_not_applicable(name):
    evaluations = _rule(name).evaluate(_state_account([make_resource(name="app-uploads")]), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.NOT_APPLICABLE, NO_RESOURCES_FOUND)}


def test_sc_006_unreadable_blob_service_is_unknown():
    evaluations = _rule("az_sc_006").evaluate(_state_account([make_resource(name="tfstate")], None), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.UNKNOWN, EVIDENCE_UNAVAILABLE)}


@pytest.mark.parametrize("name", ["az_sc_005", "az_sc_006"])
def test_sc_failed_storage_inventory_is_error(name):
    evaluations = _rule(name).evaluate(MockAzureClient().set_storage_accounts(None), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.ERROR, INVENTORY_UNAVAILABLE)}


# ── Supply chain: Azure DevOps service connections ──────────────────────────


class _DevOps:
    def __init__(self, endpoints: Any) -> None:
        self._endpoints = endpoints

    def get_service_endpoints(self) -> Any:
        return self._endpoints


def _devops(endpoints: Any) -> MockAzureClient:
    client = MockAzureClient()
    client.devops_client = _DevOps(endpoints)
    return client


def _endpoint(**overrides: Any) -> SimpleNamespace:
    fields = dict(
        id="endpoint-1",
        name="conn1",
        type="AzureRM",
        is_shared=False,
        data={"scopeLevel": "ResourceGroup", "subscriptionId": _SUB},
        authorization=SimpleNamespace(scheme="WorkloadIdentityFederation"),
    )
    fields.update(overrides)
    return SimpleNamespace(**fields)


@pytest.mark.parametrize("name", ["az_sc_007", "az_sc_008"])
def test_sc_devops_not_configured_is_not_applicable_not_error(name):
    evaluations = _rule(name).evaluate(MockAzureClient(), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.NOT_APPLICABLE, INTEGRATION_NOT_CONFIGURED)}


@pytest.mark.parametrize("name", ["az_sc_007", "az_sc_008"])
def test_sc_devops_configured_but_unreachable_is_error(name):
    evaluations = _rule(name).evaluate(_devops(None), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.ERROR, INVENTORY_UNAVAILABLE)}


@pytest.mark.parametrize("name", ["az_sc_007", "az_sc_008"])
def test_sc_only_non_azurerm_connections_is_not_applicable(name):
    evaluations = _rule(name).evaluate(_devops([_endpoint(type="GitHub")]), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.NOT_APPLICABLE, NO_RESOURCES_FOUND)}


def test_sc_007_connection_without_scope_level_is_unknown():
    evaluations = _rule("az_sc_007").evaluate(_devops([_endpoint(data={})]), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.UNKNOWN, MISSING_PROPERTIES)}


def test_sc_008_connection_without_scheme_is_unknown():
    evaluations = _rule("az_sc_008").evaluate(_devops([_endpoint(authorization=None)]), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.UNKNOWN, MISSING_PROPERTIES)}


@pytest.mark.parametrize("name", ["az_sc_007", "az_sc_008"])
def test_sc_connection_without_an_id_is_unknown_not_an_empty_finding(name):
    bad = _endpoint(
        id="", data={"scopeLevel": "Subscription"}, authorization=SimpleNamespace(scheme="ServicePrincipal")
    )

    evaluations = _rule(name).evaluate(_devops([bad]), _SUB)

    assert _statuses(evaluations) == {(EvaluationStatus.UNKNOWN, MISSING_PROPERTIES)}
    assert _rule(name).scan(_devops([bad]), _SUB) == []


# ── Through the engine ──────────────────────────────────────────────────────


def test_unconfigured_policy_and_devops_do_not_mark_rules_failed(monkeypatch):
    """A default deployment (no security-operations policy, no Azure DevOps)
    must not report these rules as failed, so the scan is not incomplete."""
    monkeypatch.delenv("OPENSHIELD_SECURITY_OPERATIONS_POLICY", raising=False)
    client = _secops_client()
    client.credential = SimpleNamespace(get_token=_raise)  # no network, whatever runs
    monkeypatch.setattr(engine_mod, "AzureClient", lambda _sub: client)
    engine = ScanEngine(_SUB)
    engine.rules = [_rule(name) for name in SECOPS_RULES + ["az_sc_007", "az_sc_008"]]

    result = engine.run_scan()

    assert result["failed_rule_ids"] == []
    assert result["findings"] == []
