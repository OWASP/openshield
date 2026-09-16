"""Direct tests for AzureClient management-plane wrappers and failure states."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from scanner.azure_client import AzureClient


@pytest.fixture
def client():
    return AzureClient("sub-1", credential=MagicMock())


def test_parse_resource_id_handles_full_and_short_ids():
    full = "/subscriptions/s/resourceGroups/RG/providers/Microsoft.Web/sites/app"
    assert AzureClient.parse_resource_id(full) == {"resource_group": "RG", "name": "app"}
    assert AzureClient.parse_resource_id("app") == {"name": "app", "resource_group": ""}


@pytest.mark.parametrize(
    ("method", "patch_target", "operation"),
    [
        ("get_storage_accounts", "scanner.azure_client.StorageManagementClient", "storage_accounts.list"),
        (
            "get_network_security_groups",
            "scanner.azure_client.NetworkManagementClient",
            "network_security_groups.list_all",
        ),
        ("get_virtual_networks", "scanner.azure_client.NetworkManagementClient", "virtual_networks.list_all"),
        ("get_public_ip_addresses", "scanner.azure_client.NetworkManagementClient", "public_ip_addresses.list_all"),
        ("get_load_balancers", "scanner.azure_client.NetworkManagementClient", "load_balancers.list_all"),
        ("get_virtual_machines", "scanner.azure_client.ComputeManagementClient", "virtual_machines.list_all"),
        ("get_postgresql_servers", "scanner.azure_client.PostgreSQLManagementClient", "servers.list"),
        ("get_sql_servers", "scanner.azure_client.SqlManagementClient", "servers.list"),
        ("get_key_vaults", "scanner.azure_client.KeyVaultManagementClient", "vaults.list_by_subscription"),
    ],
)
def test_list_wrappers_return_results_and_fail_closed(client, method, patch_target, operation):
    with patch(patch_target) as constructor:
        sdk = constructor.return_value
        target = sdk
        parts = operation.split(".")
        for part in parts[:-1]:
            target = getattr(target, part)
        call = getattr(target, parts[-1])
        call.return_value = [SimpleNamespace(name="one")]
        assert [item.name for item in getattr(client, method)()] == ["one"]

        call.side_effect = RuntimeError("Azure unavailable")
        assert getattr(client, method)() == []


def test_single_resource_and_policy_wrappers(client):
    with patch("scanner.azure_client.NetworkManagementClient") as constructor:
        constructor.return_value.network_interfaces.get.return_value = SimpleNamespace(name="nic")
        assert client.get_network_interface("rg", "nic").name == "nic"
        constructor.return_value.network_interfaces.get.side_effect = RuntimeError("denied")
        assert client.get_network_interface("rg", "nic") is None

    with patch("scanner.azure_client.SqlManagementClient") as constructor:
        policy = SimpleNamespace(state="Enabled")
        constructor.return_value.server_blob_auditing_policies.get.return_value = policy
        assert client.get_sql_server_auditing_policy("rg", "sql") is policy
        constructor.return_value.server_blob_auditing_policies.get.side_effect = RuntimeError("denied")
        assert client.get_sql_server_auditing_policy("rg", "sql") is None


def test_sql_server_entra_only_authentication_uses_child_resource(client):
    with patch("scanner.azure_client.SqlManagementClient") as constructor:
        get_authentication = constructor.return_value.server_azure_ad_only_authentications.get
        get_authentication.return_value = SimpleNamespace(azure_ad_only_authentication=True)
        assert client.get_sql_server_azure_ad_only_authentication("rg", "sql") is True
        get_authentication.assert_called_once_with("rg", "sql", "Default")
        get_authentication.side_effect = RuntimeError("denied")
        assert client.get_sql_server_azure_ad_only_authentication("rg", "sql") is None


def test_firewall_and_peering_wrappers(client):
    with patch("scanner.azure_client.NetworkManagementClient") as constructor:
        sdk = constructor.return_value
        sdk.azure_firewalls.list.return_value = [SimpleNamespace(name="fw")]
        sdk.azure_firewalls.list_all.return_value = [SimpleNamespace(name="fw-all")]
        sdk.virtual_network_peerings.list.return_value = [SimpleNamespace(name="peer")]

        assert client.get_azure_firewalls("rg")[0].name == "fw"
        assert client.get_all_azure_firewalls()[0].name == "fw-all"
        assert client.get_vnet_peerings("rg", "vnet")[0].name == "peer"

        sdk.azure_firewalls.list.side_effect = RuntimeError("denied")
        sdk.azure_firewalls.list_all.side_effect = RuntimeError("denied")
        sdk.virtual_network_peerings.list.side_effect = RuntimeError("denied")
        assert client.get_azure_firewalls("rg") == []
        assert client.get_all_azure_firewalls() is None
        assert client.get_vnet_peerings("rg", "vnet") == []


def _watcher(name, location, resource_group="NetworkWatcherRG"):
    return SimpleNamespace(
        id=f"/subscriptions/sub-1/resourceGroups/{resource_group}/providers/Microsoft.Network/networkWatchers/{name}",
        name=name,
        location=location,
    )


def test_get_flow_logs_merges_results_across_regions(client):
    with patch("scanner.azure_client.NetworkManagementClient") as constructor:
        sdk = constructor.return_value
        sdk.network_watchers.list_all.return_value = [
            _watcher("watcher-east", "East US"),
            _watcher("watcher-west", "West US"),
        ]
        sdk.flow_logs.list.side_effect = lambda rg, name: (
            [SimpleNamespace(target_resource_id="vnet-east", enabled=True)]
            if name == "watcher-east"
            else [SimpleNamespace(target_resource_id="vnet-west", enabled=False)]
        )

        result = client.get_flow_logs()

        assert set(result) == {"eastus", "westus"}
        assert result["eastus"][0].target_resource_id == "vnet-east"
        assert result["westus"][0].enabled is False


def test_get_flow_logs_top_level_failure_returns_empty_dict(client):
    """Failing to enumerate Network Watchers at all yields {} - every region
    is then indeterminate via .get(region) returning None, never a false pass."""
    with patch("scanner.azure_client.NetworkManagementClient") as constructor:
        constructor.return_value.network_watchers.list_all.side_effect = RuntimeError("denied")
        assert client.get_flow_logs() == {}


def test_get_flow_logs_partial_failure_preserves_other_regions(client):
    """One watcher's flow-log listing failing (403/429/etc) must not discard
    results already collected from a different, healthy region."""
    with patch("scanner.azure_client.NetworkManagementClient") as constructor:
        sdk = constructor.return_value
        sdk.network_watchers.list_all.return_value = [
            _watcher("watcher-ok", "East US"),
            _watcher("watcher-denied", "West US"),
        ]

        def flow_logs_list(rg, name):
            if name == "watcher-denied":
                raise RuntimeError("permission denied")
            return [SimpleNamespace(target_resource_id="vnet-east", enabled=True)]

        sdk.flow_logs.list.side_effect = flow_logs_list

        result = client.get_flow_logs()

        assert result["eastus"][0].target_resource_id == "vnet-east"
        assert result["westus"] is None


def test_vm_extensions_normalize_sdk_page_and_failure(client):
    with patch("scanner.azure_client.ComputeManagementClient") as constructor:
        constructor.return_value.virtual_machine_extensions.list.return_value = SimpleNamespace(
            value=[SimpleNamespace(name="agent")]
        )
        assert client.get_vm_extensions("rg", "vm")[0].name == "agent"
        constructor.return_value.virtual_machine_extensions.list.side_effect = RuntimeError("denied")
        assert client.get_vm_extensions("rg", "vm") is None


def test_private_endpoint_posture_one_service_failure_does_not_drop_others(client):
    """One resource type's API call failing (e.g. SQL RP not registered) must
    not discard records already collected for other resource types in the
    same call — only that service's records should be missing."""
    with (
        patch("scanner.azure_client.NetworkManagementClient") as network_ctor,
        patch("scanner.azure_client.StorageManagementClient") as storage_ctor,
        patch("scanner.azure_client.SqlManagementClient") as sql_ctor,
        patch("azure.mgmt.web.WebSiteManagementClient") as web_ctor,
        patch("azure.mgmt.postgresqlflexibleservers.PostgreSQLManagementClient") as pg_ctor,
        patch("azure.mgmt.recoveryservices.RecoveryServicesClient") as recovery_ctor,
    ):
        network_ctor.return_value.private_endpoints.list_by_subscription.return_value = []
        storage_ctor.return_value.storage_accounts.list.return_value = [
            SimpleNamespace(id="/sa1", name="sa1", public_network_access="Enabled")
        ]
        sql_ctor.return_value.servers.list.side_effect = RuntimeError("SQL RP not registered")
        web_ctor.return_value.web_apps.list.return_value = []
        pg_ctor.return_value.servers.list.return_value = []
        recovery_ctor.return_value.vaults.list_by_subscription_id.return_value = []

        records = client.get_private_endpoint_posture()

    assert records is not None
    services = {r["service"] for r in records}
    assert "storage" in services
    assert "sql" not in services


def test_private_endpoint_posture_one_web_app_failure_does_not_drop_others(client):
    """A failed configuration request for one Web App must not prevent later
    Web or Function Apps from contributing posture records."""
    with (
        patch("scanner.azure_client.NetworkManagementClient") as network_ctor,
        patch("scanner.azure_client.StorageManagementClient") as storage_ctor,
        patch("scanner.azure_client.SqlManagementClient") as sql_ctor,
        patch("azure.mgmt.web.WebSiteManagementClient") as web_ctor,
        patch("azure.mgmt.postgresqlflexibleservers.PostgreSQLManagementClient") as pg_ctor,
        patch("azure.mgmt.recoveryservices.RecoveryServicesClient") as recovery_ctor,
    ):
        network_ctor.return_value.private_endpoints.list_by_subscription.return_value = []
        storage_ctor.return_value.storage_accounts.list.return_value = []
        sql_ctor.return_value.servers.list.return_value = []
        pg_ctor.return_value.servers.list.return_value = []
        recovery_ctor.return_value.vaults.list_by_subscription_id.return_value = []
        bad_app = SimpleNamespace(id="/apps/bad", name="bad", public_network_access="Enabled")
        good_app = SimpleNamespace(id="/apps/good", name="good", public_network_access="Enabled")
        web_ctor.return_value.web_apps.list.return_value = [bad_app, good_app]

        def get_configuration(resource_group, name):
            if name == "bad":
                raise RuntimeError("configuration unavailable")
            return SimpleNamespace(public_network_access="Enabled")

        web_ctor.return_value.web_apps.get_configuration.side_effect = get_configuration

        records = client.get_private_endpoint_posture()

    assert records is not None
    assert [(record["service"], record["name"]) for record in records] == [("web", "good")]


def test_function_app_security_posture_one_app_failure_does_not_drop_others(client):
    """A single Function App's get_configuration() call failing (e.g. the app
    is stopped) must not discard posture data already collected for other
    Function Apps in the same subscription."""
    with patch("azure.mgmt.web.WebSiteManagementClient") as web_ctor:
        good_app = SimpleNamespace(id="/apps/good", name="good", kind="functionapp", https_only=True, identity=None)
        bad_app = SimpleNamespace(id="/apps/bad", name="bad", kind="functionapp", https_only=True, identity=None)
        web_ctor.return_value.web_apps.list.return_value = [good_app, bad_app]

        def get_configuration(resource_group, name):
            if name == "bad":
                raise RuntimeError("app is stopped")
            return SimpleNamespace(min_tls_version="1.2", ftps_state="Disabled", remote_debugging_enabled=False)

        web_ctor.return_value.web_apps.get_configuration.side_effect = get_configuration

        result = client.get_function_app_security_posture()

    assert result is not None
    names = {app["name"] for app in result}
    assert names == {"good"}


def test_get_container_registries_returns_results_and_caches(client):
    with patch("azure.mgmt.containerregistry.ContainerRegistryManagementClient") as constructor:
        constructor.return_value.registries.list.return_value = [SimpleNamespace(name="acr1")]
        result = client.get_container_registries()
        assert result is not None
        assert [r.name for r in result] == ["acr1"]

        # cached: second call must not hit the SDK again
        constructor.return_value.registries.list.side_effect = RuntimeError("should not be called")
        assert [r.name for r in client.get_container_registries()] == ["acr1"]


def test_get_container_registries_failure_returns_none(client):
    with patch("azure.mgmt.containerregistry.ContainerRegistryManagementClient") as constructor:
        constructor.return_value.registries.list.side_effect = RuntimeError("denied")
        assert client.get_container_registries() is None


def test_get_blob_containers_and_service_properties(client):
    with patch("scanner.azure_client.StorageManagementClient") as constructor:
        constructor.return_value.blob_containers.list.return_value = [SimpleNamespace(name="tfstate")]
        result = client.get_blob_containers("rg", "sa1")
        assert result is not None
        assert result[0].name == "tfstate"

        constructor.return_value.blob_containers.list.side_effect = RuntimeError("denied")
        assert client.get_blob_containers("rg", "sa1") is None

        constructor.return_value.blob_services.get_service_properties.return_value = SimpleNamespace(
            is_versioning_enabled=True
        )
        props = client.get_blob_service_properties("rg", "sa1")
        assert props.is_versioning_enabled is True

        constructor.return_value.blob_services.get_service_properties.side_effect = RuntimeError("denied")
        assert client.get_blob_service_properties("rg", "sa1") is None


def test_devops_client_not_built_without_env_vars(monkeypatch):
    monkeypatch.delenv("AZURE_DEVOPS_ORG_URL", raising=False)
    monkeypatch.delenv("AZURE_DEVOPS_PROJECT", raising=False)
    from scanner.azure_client import AzureClient

    fresh_client = AzureClient("sub-1", credential=MagicMock())
    assert fresh_client.devops_client is None


def test_devops_client_built_when_env_vars_present(monkeypatch):
    monkeypatch.setenv("AZURE_DEVOPS_ORG_URL", "https://dev.azure.com/test-org")
    monkeypatch.setenv("AZURE_DEVOPS_PROJECT", "test-project")
    from scanner.azure_client import AzureClient
    from scanner.devops_client import DevOpsClient

    fresh_client = AzureClient("sub-1", credential=MagicMock())
    assert isinstance(fresh_client.devops_client, DevOpsClient)
    assert fresh_client.devops_client.organization_url == "https://dev.azure.com/test-org"
    assert fresh_client.devops_client.project == "test-project"
