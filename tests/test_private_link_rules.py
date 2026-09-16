"""Offline coverage for issue #253 Private Link controls."""

from types import SimpleNamespace

import pytest

import scanner.rules.az_net_018 as az_net_018
import scanner.rules.az_net_019 as az_net_019
import scanner.rules.az_net_020 as az_net_020
import scanner.rules.az_net_021 as az_net_021
from scanner.azure_client import AzureClient


def _item(**overrides):
    item = {
        "endpoint_id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/pe1",
        "endpoint_name": "pe1",
        "resource_group": "rg",
        "location": "uksouth",
        "target_id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/store1",
        "connection_status": "Approved",
        "dns_zone_ids": [
            "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net"
        ],
        "dns_configs": [{"fqdn": "store1.blob.core.windows.net", "ip_addresses": ["10.0.0.4"]}],
        "public_network_access": False,
        "collected_at": "2026-08-17T12:00:00+00:00",
    }
    item.update(overrides)
    return item


class FakeAzure:
    def __init__(self, inventory):
        self.inventory = inventory

    def get_private_link_inventory(self):
        return self.inventory


@pytest.mark.parametrize("inventory", [[], None])
@pytest.mark.parametrize("rule", [az_net_018, az_net_019, az_net_020, az_net_021])
def test_empty_and_failed_inventory_never_create_false_findings(rule, inventory):
    assert rule.scan(FakeAzure(inventory), "sub") == []


def test_net_018_flags_public_access_and_includes_evidence():
    findings = az_net_018.scan(FakeAzure([_item(public_network_access=True)]), "sub")
    assert len(findings) == 1
    metadata = findings[0]["metadata"]
    assert metadata["evidence_source"].startswith("Azure Resource Manager")
    assert metadata["collection_timestamp"]
    assert metadata["observed"] == {"public_network_access": "Enabled"}
    assert metadata["confidence"] == "HIGH"


@pytest.mark.parametrize("status", ["Pending", "Rejected", "Disconnected"])
def test_net_019_flags_non_approved_connection_states(status):
    findings = az_net_019.scan(FakeAzure([_item(connection_status=status)]), "sub")
    assert len(findings) == 1
    assert findings[0]["metadata"]["observed"]["connection_status"] == status


@pytest.mark.parametrize("status", ["Approved", None, "unexpected"])
def test_net_019_does_not_guess_for_approved_or_unknown_state(status):
    assert az_net_019.scan(FakeAzure([_item(connection_status=status)]), "sub") == []


def test_net_020_flags_missing_zone_but_not_permission_failure():
    assert len(az_net_020.scan(FakeAzure([_item(dns_zone_ids=[])]), "sub")) == 1
    assert az_net_020.scan(FakeAzure([_item(dns_zone_ids=None)]), "sub") == []


@pytest.mark.parametrize("configs", [None, [], [{"fqdn": "broken", "ip_addresses": ["not-an-ip"]}]])
def test_net_021_unknown_or_malformed_dns_evidence_does_not_flag(configs):
    assert az_net_021.scan(FakeAzure([_item(dns_configs=configs)]), "sub") == []


def test_net_021_flags_only_public_custom_dns_configuration():
    configs = [{"fqdn": "store1.blob.core.windows.net", "ip_addresses": ["20.1.2.3"]}]
    findings = az_net_021.scan(FakeAzure([_item(dns_configs=configs)]), "sub")
    assert len(findings) == 1
    assert findings[0]["metadata"]["observed"]["non_private_custom_dns_configs"] == configs


def test_net_021_does_not_claim_effective_resolution_from_private_configuration():
    # ARM customDnsConfigs describe the endpoint's expected records. A broken
    # resolver path is outside this configuration-only rule's evidence scope.
    item = _item(effective_dns_results=["20.1.2.3"])
    assert az_net_021.scan(FakeAzure([item]), "sub") == []


def test_private_link_collector_preserves_zone_group_failure(monkeypatch):
    connection = SimpleNamespace(
        private_link_service_id=_item()["target_id"],
        private_link_service_connection_state=SimpleNamespace(status="Approved"),
    )
    endpoint = SimpleNamespace(
        id=_item()["endpoint_id"],
        name="pe1",
        location="uksouth",
        private_link_service_connections=[connection],
        manual_private_link_service_connections=[],
        custom_dns_configs=[],
    )
    network = SimpleNamespace(
        private_endpoints=SimpleNamespace(list_by_subscription=lambda: [endpoint]),
        private_dns_zone_groups=SimpleNamespace(list=lambda *_: (_ for _ in ()).throw(PermissionError("denied"))),
    )
    monkeypatch.setattr("scanner.azure_client.NetworkManagementClient", lambda *_: network)
    monkeypatch.setattr(AzureClient, "_get_private_link_target_public_access", lambda *_: False)
    inventory = AzureClient("sub", credential=object()).get_private_link_inventory()
    assert inventory is not None
    assert inventory[0]["dns_zone_ids"] is None


def test_private_link_collector_list_failure_is_unknown(monkeypatch):
    network = SimpleNamespace(
        private_endpoints=SimpleNamespace(list_by_subscription=lambda: (_ for _ in ()).throw(PermissionError("denied")))
    )
    monkeypatch.setattr("scanner.azure_client.NetworkManagementClient", lambda *_: network)
    assert AzureClient("sub", credential=object()).get_private_link_inventory() is None
