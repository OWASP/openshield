"""Shared MockAzureClient for rule regression tests.

Provides a configurable in-memory replacement for the real AzureClient so that
scanner rule unit tests can run fully offline with no Azure credentials.

Usage:
    from tests.helpers.mock_azure import MockAzureClient, make_resource

    client = MockAzureClient()
    client.set_storage_accounts([
        make_resource(id="/sub/rg/sa", name="mystorage", allow_blob_public_access=True)
    ])
    findings = az_stor_001.scan(client, "sub-id")
"""

from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple


def make_resource(**kwargs: Any) -> SimpleNamespace:
    """Build a fake Azure resource object with arbitrary attributes."""
    return SimpleNamespace(**kwargs)


class _StubToken:
    """Minimal stand-in for an Azure AccessToken (has a ``.token`` attribute)."""

    def __init__(self, token: str = "fake-graph-token") -> None:
        self.token = token


class _StubCredential:
    """Minimal stand-in for a TokenCredential used by Graph/SDK-based rules.

    Rules that talk to Microsoft Graph or instantiate an Azure management
    client read ``azure_client.credential`` and call ``get_token(scope)``.
    Tests monkeypatch ``requests.get`` / the SDK client class separately, so
    this stub only needs to hand back an object exposing ``.token``.
    """

    def get_token(self, *scopes: Any, **kwargs: Any) -> _StubToken:
        return _StubToken()


class MockAzureClient:
    """Drop-in replacement for AzureClient that returns configured fake data."""

    def __init__(self) -> None:
        self._storage_accounts: List[Any] = []
        self._network_security_groups: List[Any] = []
        self._express_route_ports: Optional[List[Any]] = []
        self._virtual_machines: List[Any] = []
        self._virtual_machine_scale_sets: List[Any] = []
        self._key_vaults: List[Any] = []
        self._sql_servers: List[Any] = []
        self._service_principals: List[Any] = []
        self._sql_firewall_rules: Dict[Tuple[str, str], List[Any]] = {}
        # --- Additional state added for full rule-coverage tests ---------- #
        self._network_interfaces: Dict[Tuple[str, str], Any] = {}
        self._all_network_interfaces: Optional[List[Any]] = []
        self._route_tables: Optional[List[Any]] = []
        self._vm_extensions: Dict[Tuple[str, str], Optional[List[Any]]] = {}
        self._disks: Dict[str, Optional[Any]] = {}
        self._storage_lifecycle: Dict[Tuple[str, str], Optional[bool]] = {}
        self._storage_logging: Dict[Tuple[str, str, str], Optional[bool]] = {}
        self._virtual_networks: List[Any] = []
        self._public_ip_addresses: List[Any] = []
        self._load_balancers: List[Any] = []
        self._all_azure_firewalls: Optional[List[Any]] = []
        self._vnet_peerings: Dict[Tuple[str, str], List[Any]] = {}
        self._postgresql_servers: List[Any] = []
        self._postgresql_flexible_servers: List[Any] = []
        self._pg_flex_parameters: Dict[Tuple[str, str], List[Any]] = {}
        self._sql_auditing: Dict[Tuple[str, str], Any] = {}
        self._sql_auditing_default: Any = None
        self._kv_certificates: Dict[str, List[Any]] = {}
        self._kv_keys: Dict[str, List[Any]] = {}
        self._diagnostic_settings: Dict[str, Optional[bool]] = {}
        self._diagnostic_default: Optional[bool] = False
        self._jit_policies: Optional[List[Any]] = []
        self._conditional_access_policies: List[Any] = []
        # Credential stub for Graph/SDK-based rules (idn_003..009).
        self.credential = _StubCredential()
        self._regions_with_resources: List[str] = []
        self._network_watcher_regions: List[str] = []
        self._flow_logs_by_region: Dict[str, Optional[List[Any]]] = {}
        self._dns_zones: List[Any] = []
        self._dns_record_sets: Dict[Tuple[str, str], List[Any]] = {}
        self._web_apps: List[Any] = []
        self._managed_clusters: Optional[List[Any]] = []
        self._applications: Optional[List[Dict[str, Any]]] = []
        self._managed_identity_principals: Optional[List[Dict[str, Any]]] = []
        self._subscription_role_assignments: Optional[List[Any]] = []
        self._container_registries: Optional[List[Any]] = []
        self._blob_containers: Dict[Tuple[str, str], Optional[List[Any]]] = {}
        self._blob_service_properties: Dict[Tuple[str, str], Optional[Any]] = {}
        # None by default, matching AzureClient.devops_client's "not configured" state.
        self.devops_client: Optional[Any] = None
        # Privileged access / identity collectors (issue #258)
        self._privileged_role_members: Optional[List[Dict[str, Any]]] = []
        self._privileged_users_mfa_methods: Optional[List[Dict[str, Any]]] = []
        self._pim_role_assignments: Optional[List[Dict[str, Any]]] = []
        self._identity_protection_policies: Optional[Dict[str, Any]] = {
            "userRiskPolicy": {"isEnabled": True, "riskLevel": "medium"},
            "signInRiskPolicy": {"isEnabled": True, "riskLevel": "medium"},
        }
        self._privileged_groups: Optional[List[Dict[str, Any]]] = []
        # Some rules read azure_client.subscription_id when constructing an
        # SDK management client inside scan() (e.g. AZ-NET-007..010).
        self.subscription_id = "00000000-0000-0000-0000-000000000001"

    def set_storage_accounts(self, accounts: List[Any]) -> "MockAzureClient":
        self._storage_accounts = accounts
        return self

    def set_express_route_ports(self, ports: Optional[List[Any]]) -> "MockAzureClient":
        """Configure ExpressRoute Direct inventory; ``None`` represents an API failure."""
        self._express_route_ports = ports
        return self

    def get_express_route_ports(self) -> Optional[List[Any]]:
        return self._express_route_ports

    def set_network_interfaces(self, interfaces: Optional[List[Any]]) -> "MockAzureClient":
        self._all_network_interfaces = interfaces
        return self

    def get_network_interfaces(self) -> Optional[List[Any]]:
        return self._all_network_interfaces

    def set_route_tables(self, route_tables: Optional[List[Any]]) -> "MockAzureClient":
        self._route_tables = route_tables
        return self

    def get_route_tables(self) -> Optional[List[Any]]:
        return self._route_tables

    def set_managed_clusters(self, clusters: Optional[List[Any]]) -> "MockAzureClient":
        """Configure AKS inventory; ``None`` represents an API failure."""
        self._managed_clusters = clusters
        return self

    def get_managed_clusters(self) -> Optional[List[Any]]:
        return self._managed_clusters

    def set_applications(self, applications: Optional[List[Dict[str, Any]]]) -> "MockAzureClient":
        self._applications = applications
        return self

    def get_applications(self) -> Optional[List[Dict[str, Any]]]:
        return self._applications

    def set_managed_identity_service_principals(self, principals: Optional[List[Dict[str, Any]]]) -> "MockAzureClient":
        self._managed_identity_principals = principals
        return self

    def get_managed_identity_service_principals(self) -> Optional[List[Dict[str, Any]]]:
        return self._managed_identity_principals

    def set_subscription_role_assignments(self, assignments: Optional[List[Any]]) -> "MockAzureClient":
        self._subscription_role_assignments = assignments
        return self

    def get_subscription_role_assignments(self) -> Optional[List[Any]]:
        return self._subscription_role_assignments

    def set_container_registries(self, registries: Optional[List[Any]]) -> "MockAzureClient":
        """Configure Container Registry inventory; ``None`` represents an API failure."""
        self._container_registries = registries
        return self

    def get_container_registries(self) -> Optional[List[Any]]:
        return self._container_registries

    def set_blob_containers(
        self, resource_group: str, account_name: str, containers: Optional[List[Any]]
    ) -> "MockAzureClient":
        """Configure per-account blob container listing; ``None`` represents an API failure."""
        self._blob_containers[(resource_group, account_name)] = containers
        return self

    def get_blob_containers(self, resource_group: str, account_name: str) -> Optional[List[Any]]:
        return self._blob_containers.get((resource_group, account_name), None)

    def set_blob_service_properties(
        self, resource_group: str, account_name: str, properties: Optional[Any]
    ) -> "MockAzureClient":
        """Configure per-account blob service properties; ``None`` represents an API failure."""
        self._blob_service_properties[(resource_group, account_name)] = properties
        return self

    def get_blob_service_properties(self, resource_group: str, account_name: str) -> Optional[Any]:
        return self._blob_service_properties.get((resource_group, account_name), None)

    def set_network_security_groups(self, nsgs: List[Any]) -> "MockAzureClient":
        self._network_security_groups = nsgs
        return self

    def set_virtual_machines(self, vms: List[Any]) -> "MockAzureClient":
        self._virtual_machines = vms
        return self

    def set_virtual_machine_scale_sets(self, scale_sets: List[Any]) -> "MockAzureClient":
        self._virtual_machine_scale_sets = scale_sets
        return self

    def set_key_vaults(self, vaults: List[Any]) -> "MockAzureClient":
        self._key_vaults = vaults
        return self

    def set_sql_servers(self, servers: List[Any]) -> "MockAzureClient":
        self._sql_servers = servers
        return self

    def set_service_principals(self, principals: List[Any]) -> "MockAzureClient":
        self._service_principals = principals
        return self

    def set_sql_server_firewall_rules(
        self, resource_group: str, server_name: str, rules: List[Any]
    ) -> "MockAzureClient":
        self._sql_firewall_rules[(resource_group, server_name)] = rules
        return self

    def get_storage_accounts(self) -> List[Any]:
        return self._storage_accounts

    def get_network_security_groups(self) -> List[Any]:
        return self._network_security_groups

    def get_virtual_machines(self) -> List[Any]:
        return self._virtual_machines

    def get_virtual_machine_scale_sets(self) -> List[Any]:
        return self._virtual_machine_scale_sets

    def get_key_vaults(self) -> List[Any]:
        return self._key_vaults

    def get_sql_servers(self) -> List[Any]:
        return self._sql_servers

    def get_service_principals(self) -> List[Any]:
        return self._service_principals

    def get_sql_server_firewall_rules(self, resource_group: str, server_name: str) -> List[Any]:
        return self._sql_firewall_rules.get((resource_group, server_name), [])

    # ------------------------------------------------------------------ #
    # Compute — network interfaces & VM extensions                          #
    # ------------------------------------------------------------------ #

    def set_network_interface(self, resource_group: str, nic_name: str, nic: Any) -> "MockAzureClient":
        self._network_interfaces[(resource_group, nic_name)] = nic
        return self

    def get_network_interface(self, resource_group: str, nic_name: str) -> Optional[Any]:
        return self._network_interfaces.get((resource_group, nic_name))

    def set_vm_extensions(
        self, resource_group: str, vm_name: str, extensions: Optional[List[Any]]
    ) -> "MockAzureClient":
        self._vm_extensions[(resource_group, vm_name)] = extensions
        return self

    def get_vm_extensions(self, resource_group: str, vm_name: str) -> Optional[List[Any]]:
        # Default to an empty list (compliant-by-default) unless configured.
        return self._vm_extensions.get((resource_group, vm_name), [])

    def set_disk(self, disk_id: str, disk: Optional[Any]) -> "MockAzureClient":
        """Configure the Disk resource returned for a managed disk ID; ``None`` represents an unreadable disk."""
        self._disks[disk_id] = disk
        return self

    def get_disk(self, disk_id: str) -> Optional[Any]:
        return self._disks.get(disk_id)

    def set_jit_policies(self, policies: Optional[List[Any]]) -> "MockAzureClient":
        """Configure the Defender for Cloud JIT policies; ``None`` represents an unreadable/indeterminate result."""
        self._jit_policies = policies
        return self

    def get_jit_network_access_policies(self) -> Optional[List[Any]]:
        return self._jit_policies

    # ------------------------------------------------------------------ #
    # Storage — lifecycle & service logging (three-state: True/False/None) #
    # ------------------------------------------------------------------ #

    def set_storage_lifecycle_policy(
        self, resource_group: str, account_name: str, value: Optional[bool]
    ) -> "MockAzureClient":
        self._storage_lifecycle[(resource_group, account_name)] = value
        return self

    def get_storage_lifecycle_policy(self, resource_group: str, account_name: str) -> Optional[bool]:
        return self._storage_lifecycle.get((resource_group, account_name))

    def set_storage_service_logging(
        self, resource_group: str, account_name: str, service: str, value: Optional[bool]
    ) -> "MockAzureClient":
        self._storage_logging[(resource_group, account_name, service)] = value
        return self

    def get_storage_service_logging(self, resource_group: str, account_name: str, service: str) -> Optional[bool]:
        return self._storage_logging.get((resource_group, account_name, service))

    # ------------------------------------------------------------------ #
    # Network — VNets, public IPs, firewalls, peerings, flow logs           #
    # ------------------------------------------------------------------ #

    def set_virtual_networks(self, vnets: List[Any]) -> "MockAzureClient":
        self._virtual_networks = vnets
        return self

    def get_virtual_networks(self) -> List[Any]:
        return self._virtual_networks

    def set_public_ip_addresses(self, ips: List[Any]) -> "MockAzureClient":
        self._public_ip_addresses = ips
        return self

    def get_public_ip_addresses(self) -> List[Any]:
        return self._public_ip_addresses

    def set_load_balancers(self, load_balancers: List[Any]) -> "MockAzureClient":
        self._load_balancers = load_balancers
        return self

    def get_load_balancers(self) -> List[Any]:
        return self._load_balancers

    def set_all_azure_firewalls(self, firewalls: Optional[List[Any]]) -> "MockAzureClient":
        self._all_azure_firewalls = firewalls
        return self

    def get_all_azure_firewalls(self) -> Optional[List[Any]]:
        return self._all_azure_firewalls

    def set_vnet_peerings(self, resource_group: str, vnet_name: str, peerings: List[Any]) -> "MockAzureClient":
        self._vnet_peerings[(resource_group, vnet_name)] = peerings
        return self

    def get_vnet_peerings(self, resource_group: str, vnet_name: str) -> List[Any]:
        return self._vnet_peerings.get((resource_group, vnet_name), [])

    def set_flow_logs_by_region(self, region: str, flow_logs: Optional[List[Any]]) -> "MockAzureClient":
        # ``None`` models a region whose Network Watcher/flow-log listing
        # failed (or wasn't set at all - regions absent from this dict are
        # the same case). A region simply never set here means "no Network
        # Watcher found there", matching AzureClient.get_flow_logs()'s contract.
        self._flow_logs_by_region[region] = flow_logs
        return self

    def get_flow_logs(self) -> Dict[str, Optional[List[Any]]]:
        return self._flow_logs_by_region

    def set_regions_with_resources(self, regions: List[str]) -> "MockAzureClient":
        self._regions_with_resources = regions
        return self

    def get_regions_with_resources(self) -> List[str]:
        return self._regions_with_resources

    def set_network_watcher_regions(self, regions: List[str]) -> "MockAzureClient":
        self._network_watcher_regions = regions
        return self

    def get_network_watcher_regions(self) -> List[str]:
        return self._network_watcher_regions

    def set_dns_zones(self, zones: List[Any]) -> "MockAzureClient":
        self._dns_zones = zones
        return self

    def get_dns_zones(self) -> List[Any]:
        return self._dns_zones

    def set_dns_record_sets(self, resource_group: str, zone_name: str, record_sets: List[Any]) -> "MockAzureClient":
        self._dns_record_sets[(resource_group, zone_name)] = record_sets
        return self

    def get_dns_record_sets(self, resource_group: str, zone_name: str) -> List[Any]:
        return self._dns_record_sets.get((resource_group, zone_name), [])

    # ------------------------------------------------------------------ #
    # Databases — PostgreSQL (single + flexible), SQL auditing               #
    # ------------------------------------------------------------------ #

    def set_postgresql_servers(self, servers: List[Any]) -> "MockAzureClient":
        self._postgresql_servers = servers
        return self

    def get_postgresql_servers(self) -> List[Any]:
        return self._postgresql_servers

    def set_postgresql_flexible_servers(self, servers: List[Any]) -> "MockAzureClient":
        self._postgresql_flexible_servers = servers
        return self

    def get_postgresql_flexible_servers(self) -> List[Any]:
        return self._postgresql_flexible_servers

    def set_postgresql_flexible_server_parameters(
        self, resource_group: str, server_name: str, parameters: List[Any]
    ) -> "MockAzureClient":
        self._pg_flex_parameters[(resource_group, server_name)] = parameters
        return self

    def get_postgresql_flexible_server_parameters(self, resource_group: str, server_name: str) -> List[Any]:
        return self._pg_flex_parameters.get((resource_group, server_name), [])

    def set_sql_server_auditing_policy(self, resource_group: str, server_name: str, policy: Any) -> "MockAzureClient":
        self._sql_auditing[(resource_group, server_name)] = policy
        return self

    def get_sql_server_auditing_policy(self, resource_group: str, server_name: str) -> Optional[Any]:
        return self._sql_auditing.get((resource_group, server_name), self._sql_auditing_default)

    # ------------------------------------------------------------------ #
    # Key Vault — certificates & keys (data plane)                          #
    # ------------------------------------------------------------------ #

    def set_key_vault_certificates(self, vault_name: str, certificates: List[Any]) -> "MockAzureClient":
        self._kv_certificates[vault_name] = certificates
        return self

    def get_key_vault_certificates(self, vault_name: str) -> List[Any]:
        return self._kv_certificates.get(vault_name, [])

    def set_key_vault_keys(self, vault_name: str, keys: List[Any]) -> "MockAzureClient":
        self._kv_keys[vault_name] = keys
        return self

    def get_key_vault_keys(self, vault_name: str) -> List[Any]:
        return self._kv_keys.get(vault_name, [])

    # ------------------------------------------------------------------ #
    # Monitoring & Identity                                                 #
    # ------------------------------------------------------------------ #

    def set_diagnostic_settings(self, resource_id: str, value: Optional[bool]) -> "MockAzureClient":
        self._diagnostic_settings[resource_id] = value
        return self

    def get_diagnostic_settings(self, resource_id: str) -> Optional[bool]:
        return self._diagnostic_settings.get(resource_id, self._diagnostic_default)

    def set_conditional_access_policies(self, policies: List[Any]) -> "MockAzureClient":
        self._conditional_access_policies = policies
        return self

    def get_conditional_access_policies(self) -> List[Any]:
        return self._conditional_access_policies

    def set_web_apps(self, apps: List[Any]) -> "MockAzureClient":
        self._web_apps = apps
        return self

    def get_web_apps(self) -> List[Any]:
        return self._web_apps

    # ------------------------------------------------------------------ #
    # Privileged Access & Identity (issue #258)                            #
    # ------------------------------------------------------------------ #

    def set_privileged_role_members(self, members: Optional[List[Dict[str, Any]]]) -> "MockAzureClient":
        self._privileged_role_members = members
        return self

    def get_privileged_role_members(self) -> Optional[List[Dict[str, Any]]]:
        return self._privileged_role_members

    def set_privileged_users_mfa_methods(self, methods: Optional[List[Dict[str, Any]]]) -> "MockAzureClient":
        self._privileged_users_mfa_methods = methods
        return self

    def get_privileged_users_mfa_methods(self) -> Optional[List[Dict[str, Any]]]:
        return self._privileged_users_mfa_methods

    def set_pim_role_assignments(self, assignments: Optional[List[Dict[str, Any]]]) -> "MockAzureClient":
        self._pim_role_assignments = assignments
        return self

    def get_pim_role_assignments(self) -> Optional[List[Dict[str, Any]]]:
        return self._pim_role_assignments

    def set_identity_protection_policies(self, policies: Optional[Dict[str, Any]]) -> "MockAzureClient":
        self._identity_protection_policies = policies
        return self

    def get_identity_protection_policies(self) -> Optional[Dict[str, Any]]:
        return self._identity_protection_policies

    def set_privileged_groups(self, groups: Optional[List[Dict[str, Any]]]) -> "MockAzureClient":
        self._privileged_groups = groups
        return self

    def get_privileged_groups(self) -> Optional[List[Dict[str, Any]]]:
        return self._privileged_groups

    @staticmethod
    def parse_resource_id(resource_id: str) -> Dict[str, str]:
        """Parse an Azure resource ID into a dict with name and resource_group.

        Always returns both keys, even for malformed or empty IDs, so
        callers can safely use parsed["resource_group"] without risking
        a KeyError.
        """
        parts = (resource_id or "").split("/")
        result: Dict[str, str] = {
            "name": parts[-1] if parts else "",
            "resource_group": "",
        }
        for idx, segment in enumerate(parts):
            if segment.lower() == "resourcegroups" and idx + 1 < len(parts):
                result["resource_group"] = parts[idx + 1]
        return result
