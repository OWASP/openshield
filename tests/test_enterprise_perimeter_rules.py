"""Offline positive, negative, empty, malformed, and failure tests for issue #253 rules 5–10."""

from types import SimpleNamespace

import pytest

import scanner.rules.az_net_022 as az_net_022
import scanner.rules.az_net_023 as az_net_023
import scanner.rules.az_net_024 as az_net_024
import scanner.rules.az_net_025 as az_net_025
import scanner.rules.az_net_026 as az_net_026
import scanner.rules.az_net_027 as az_net_027
from scanner.azure_client import AzureClient


def ns(**values):
    return SimpleNamespace(**values)


_GATEWAY_ID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/appgw"
_POLICY_ID = (
    "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/"
    "ApplicationGatewayWebApplicationFirewallPolicies/waf"
)


def gateway(*, public=True, mode="Prevention", policy=True, enabled=True, sku="WAF_v2"):
    return ns(
        id=_GATEWAY_ID,
        name="appgw",
        web_application_firewall_configuration=ns(
            enabled=enabled, firewall_mode=mode, rule_set_type="OWASP", rule_set_version="3.2"
        ),
        firewall_policy=ns(id=_POLICY_ID) if policy else None,
        frontend_ip_configurations=[ns(public_ip_address=ns(id="/publicIps/pip"))] if public else [],
        sku=ns(name=sku),
    )


def policy(*, mode="Prevention", current=True, bot=True, rate=True):
    sets = []
    if current:
        sets.append(ns(rule_set_type="OWASP", rule_set_version="3.2"))
    if bot:
        sets.append(ns(rule_set_type="Microsoft_BotManagerRuleSet", rule_set_version="1.0"))
    custom = [ns(rule_type="RateLimitRule", state="Enabled")] if rate else []
    return ns(
        id=_POLICY_ID,
        policy_settings=ns(mode=mode),
        managed_rules=ns(managed_rule_sets=sets),
        custom_rules=custom,
    )


class FakeAzure:
    def __init__(self, *, paas=None, firewalls=None, gateways=None, policies=None, diagnostics=True):
        self.paas = {} if paas is None else paas
        self.firewalls = [] if firewalls is None else firewalls
        self.gateways = [] if gateways is None else gateways
        self.policies = [] if policies is None else policies
        self.diagnostics = diagnostics

    def get_critical_paas_inventory(self):
        return self.paas

    def get_all_azure_firewalls(self):
        return self.firewalls

    def get_application_gateways(self):
        return self.gateways

    def get_waf_policies(self):
        return self.policies

    def get_waf_diagnostic_logging(self, resource_id, sku_name):
        return self.diagnostics


def paas_item(public=True):
    return {
        "resource_id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/store",
        "resource_name": "store",
        "resource_type": "Microsoft.Storage/storageAccounts",
        "resource_group": "rg",
        "location": "uksouth",
        "public_network_access": public,
        "collected_at": "2026-08-17T12:00:00+00:00",
    }


@pytest.mark.parametrize(
    "rule,client",
    [
        (az_net_022, FakeAzure(paas={"storage": []})),
        (az_net_023, FakeAzure(firewalls=[])),
        (az_net_024, FakeAzure(gateways=[], policies=[])),
        (az_net_025, FakeAzure(gateways=[])),
        (az_net_026, FakeAzure(gateways=[], policies=[])),
        (az_net_027, FakeAzure(gateways=[], policies=[])),
    ],
)
def test_empty_inventory_is_not_applicable(rule, client):
    assert rule.scan(client, "sub") == []


def test_net_022_public_paas_flags_and_exception_suppresses(monkeypatch):
    item = paas_item()
    client = FakeAzure(paas={"storage": [item], "sql": None})
    findings = az_net_022.scan(client, "sub")
    assert len(findings) == 1
    assert findings[0]["metadata"]["observed"]["approved_exception"] is False
    monkeypatch.setenv("OPENSHIELD_PUBLIC_PAAS_EXCEPTIONS", item["resource_id"])
    assert az_net_022.scan(client, "sub") == []


@pytest.mark.parametrize("state", [False, None])
def test_net_022_private_or_unknown_state_does_not_flag(state):
    assert az_net_022.scan(FakeAzure(paas={"storage": [paas_item(state)]}), "sub") == []


@pytest.mark.parametrize("mode", ["Alert", "Off"])
def test_net_023_flags_real_non_deny_modes(mode):
    firewall = ns(
        id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw",
        name="fw",
        threat_intel_mode=mode,
    )
    assert len(az_net_023.scan(FakeAzure(firewalls=[firewall]), "sub")) == 1


def test_net_023_accepts_real_deny_mode_and_preserves_unknown():
    firewall = ns(
        id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw",
        name="fw",
        threat_intel_mode=ns(value="Deny"),
    )
    assert az_net_023.scan(FakeAzure(firewalls=[firewall]), "sub") == []
    firewall.threat_intel_mode = None
    assert az_net_023.scan(FakeAzure(firewalls=[firewall]), "sub") == []
    firewall.threat_intel_mode = "FutureMode"
    assert az_net_023.scan(FakeAzure(firewalls=[firewall]), "sub") == []
    assert az_net_023.scan(FakeAzure(firewalls=None), "sub") == []


def test_net_024_detection_flags_and_prevention_passes():
    gw = gateway()
    assert len(az_net_024.scan(FakeAzure(gateways=[gw], policies=[policy(mode="Detection")]), "sub")) == 1
    assert az_net_024.scan(FakeAzure(gateways=[gw], policies=[policy(mode="Prevention")]), "sub") == []


def test_net_024_missing_inventory_or_mode_is_unknown():
    assert az_net_024.scan(FakeAzure(gateways=None, policies=[]), "sub") == []
    gw = gateway(mode=None, policy=False)
    assert az_net_024.scan(FakeAzure(gateways=[gw], policies=[]), "sub") == []


def test_net_025_diagnostics_positive_negative_and_failure():
    gw = gateway()
    assert az_net_025.scan(FakeAzure(gateways=[gw], diagnostics=True), "sub") == []
    assert len(az_net_025.scan(FakeAzure(gateways=[gw], diagnostics=False), "sub")) == 1
    assert az_net_025.scan(FakeAzure(gateways=[gw], diagnostics=None), "sub") == []


@pytest.mark.parametrize("current,bot,expected", [(True, True, 0), (False, True, 1), (True, False, 1)])
def test_net_026_requires_current_base_and_bot_rules(current, bot, expected):
    findings = az_net_026.scan(FakeAzure(gateways=[gateway()], policies=[policy(current=current, bot=bot)]), "sub")
    assert len(findings) == expected


def test_net_026_malformed_managed_rules_is_unknown():
    malformed = ns(id=_POLICY_ID, policy_settings=ns(mode="Prevention"), managed_rules=None, custom_rules=[])
    assert az_net_026.scan(FakeAzure(gateways=[gateway()], policies=[malformed]), "sub") == []


def test_net_027_public_gateway_requires_enabled_rate_limit():
    gw = gateway(public=True)
    assert az_net_027.scan(FakeAzure(gateways=[gw], policies=[policy(rate=True)]), "sub") == []
    assert len(az_net_027.scan(FakeAzure(gateways=[gw], policies=[policy(rate=False)]), "sub")) == 1
    disabled_policy = policy(rate=False)
    disabled_policy.custom_rules = [ns(rule_type="RateLimitRule", state="Disabled")]
    assert len(az_net_027.scan(FakeAzure(gateways=[gw], policies=[disabled_policy]), "sub")) == 1
    assert az_net_027.scan(FakeAzure(gateways=[gateway(public=False)], policies=[policy(rate=False)]), "sub") == []


def test_net_027_ignores_public_gateway_without_waf():
    gw = gateway(public=True, policy=False, enabled=False)
    assert az_net_027.scan(FakeAzure(gateways=[gw], policies=[]), "sub") == []


@pytest.mark.parametrize("state", [None, "FutureState"])
def test_net_027_preserves_unknown_rate_limit_state(state):
    rate_rule = ns(rule_type="RateLimitRule")
    if state is not None:
        rate_rule.state = state
    waf_policy = policy(rate=False)
    waf_policy.custom_rules = [rate_rule]
    assert az_net_027.scan(FakeAzure(gateways=[gateway()], policies=[waf_policy]), "sub") == []


def test_diagnostic_collector_requires_v1_performance_category(monkeypatch):
    logs = [
        ns(category="ApplicationGatewayAccessLog", enabled=True),
        ns(category="ApplicationGatewayFirewallLog", enabled=True),
    ]
    monitor = ns(diagnostic_settings=ns(list=lambda _: [ns(logs=logs)]))
    monkeypatch.setattr("scanner.azure_client.MonitorManagementClient", lambda *_: monitor)
    client = AzureClient("sub", credential=object())
    assert client.get_waf_diagnostic_logging(_GATEWAY_ID, "WAF_Medium") is False
    logs.append(ns(category="ApplicationGatewayPerformanceLog", enabled=True))
    assert client.get_waf_diagnostic_logging(_GATEWAY_ID, "WAF_Medium") is True


def test_diagnostic_collector_accepts_wafv2_without_performance_log(monkeypatch):
    logs = [
        ns(category="ApplicationGatewayAccessLog", enabled=True),
        ns(category="ApplicationGatewayFirewallLog", enabled=True),
    ]
    monitor = ns(diagnostic_settings=ns(list=lambda _: [ns(logs=logs)]))
    monkeypatch.setattr("scanner.azure_client.MonitorManagementClient", lambda *_: monitor)
    client = AzureClient("sub", credential=object())
    assert client.get_waf_diagnostic_logging(_GATEWAY_ID, "WAF_v2") is True
    logs.pop()
    assert client.get_waf_diagnostic_logging(_GATEWAY_ID, "WAF_v2") is False


def test_critical_paas_collector_preserves_independent_service_failure(monkeypatch):
    client = AzureClient("sub", credential=object())
    monkeypatch.setattr(client, "_collect_public_storage_accounts", lambda _: [paas_item(False)])
    monkeypatch.setattr(client, "_collect_public_key_vaults", lambda _: (_ for _ in ()).throw(PermissionError()))
    monkeypatch.setattr(client, "_collect_public_sql_servers", lambda _: [])
    monkeypatch.setattr(client, "_collect_public_postgresql_servers", lambda _: [])
    monkeypatch.setattr(client, "_collect_public_web_apps", lambda _: [])
    result = client.get_critical_paas_inventory()
    assert result["storage"] == [paas_item(False)]
    assert result["key_vault"] is None
