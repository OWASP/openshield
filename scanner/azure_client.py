"""Azure SDK wrapper providing typed accessors for all CSPM scan operations."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.rdbms.postgresql import PostgreSQLManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.storage import StorageManagementClient


logger = logging.getLogger(__name__)

# Azure built-in role definition GUIDs (subscription-scoped)
OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
_UNSET = object()


def enum_str(value: Any, default: str = "") -> str:
    """Safely coerce an Azure SDK field to its plain string form.

    Azure SDK models often return fields typed as enums (e.g.
    SecurityRuleDirection, BlobAuditingPolicyState) rather than plain
    strings. ``str(enum_member)`` yields something like
    "SecurityRuleDirection.INBOUND", not the underlying value "Inbound",
    which breaks naive string comparisons. This prefers ``.value`` when
    present (covers real SDK enums and enum-like objects) and falls back
    to ``str()`` for plain strings, None, or anything else.
    """
    if value is None:
        return default
    return str(getattr(value, "value", value))


class AzureClient:
    """Wraps Azure SDK management clients for all CSPM scan operations.

    Instantiate once per scan and share across all rule modules. Every method
    logs on failure and returns an empty list so individual rule failures never
    crash the scan engine.
    """

    def __init__(self, subscription_id: str, credential: Optional[Any] = None) -> None:
        self.subscription_id = subscription_id
        self.credential = credential or DefaultAzureCredential()
        self._managed_clusters_cache: Any = _UNSET
        self._function_apps_cache: Any = _UNSET
        self._private_endpoint_posture_cache: Any = _UNSET
        self._recovery_vaults_cache: Any = _UNSET
        self._applications_cache: Any = _UNSET
        self._managed_identity_principals_cache: Any = _UNSET
        self._subscription_role_assignments_cache: Any = _UNSET
        self._container_registries_cache: Any = _UNSET
        self._critical_paas_cache: Any = _UNSET
        self._application_gateways_cache: Any = _UNSET
        self._waf_policies_cache: Any = _UNSET
        self._disks_cache: Dict[str, Any] = {}
        self.devops_client = self._build_devops_client()

    def _build_devops_client(self) -> Optional[Any]:
        """Return a DevOpsClient if AZURE_DEVOPS_ORG_URL and AZURE_DEVOPS_PROJECT
        are configured, else None. Absence is a deliberate opt-out (not every
        subscription has an associated Azure DevOps organization), so rules
        that depend on this must treat None as "not configured, skip" rather
        than "unknown, indeterminate"."""
        import os

        org_url = os.environ.get("AZURE_DEVOPS_ORG_URL")
        project = os.environ.get("AZURE_DEVOPS_PROJECT")
        if not org_url or not project:
            return None

        from scanner.devops_client import DevOpsClient

        return DevOpsClient(org_url, project, credential=self.credential)

    # ------------------------------------------------------------------ #
    # Static helpers                                                        #
    # ------------------------------------------------------------------ #

    @staticmethod
    def parse_resource_id(resource_id: str) -> Dict[str, str]:
        """Return resource_group and name parsed from an Azure resource ID.

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

    # ------------------------------------------------------------------ #
    # Storage                                                               #
    # ------------------------------------------------------------------ #

    def get_storage_accounts(self) -> List[Any]:
        """List all storage accounts in the subscription."""
        try:
            client = StorageManagementClient(self.credential, self.subscription_id)
            return list(client.storage_accounts.list())
        except Exception as exc:
            logger.error("get_storage_accounts failed: %s", exc)
            return []

    def get_storage_lifecycle_policy(self, resource_group: str, account_name: str) -> Optional[bool]:
        """Check whether a storage account has a lifecycle management policy.

        Three-state return - the calling rule uses strict identity checks
        (is False / is None) to distinguish these states:

            True  - policy exists and contains at least one enabled rule.
            False - ResourceNotFoundError: no policy configured (non-compliant).
            None  - any other error (permissions, network, SDK bug).
                    Caller must NOT create a finding - skip with a warning
                    to avoid false positives.

        Args:
            resource_group: Resource group containing the storage account.
            account_name:   Name of the storage account.

        Returns:
            Optional[bool] - True, False, or None as described above.
        """
        try:
            client = StorageManagementClient(self.credential, self.subscription_id)
            policy = client.management_policies.get(resource_group, account_name, "default")
            rules = getattr(getattr(policy, "policy", None), "rules", None)
            return bool(rules)

        except ResourceNotFoundError:
            logger.debug(
                "get_storage_lifecycle_policy(%s): ResourceNotFound - no policy",
                account_name,
            )
            return False

        except HttpResponseError as exc:
            logger.error(
                "get_storage_lifecycle_policy(%s) HTTP %s - check service principal permissions: %s",
                account_name,
                exc.status_code,
                exc,
            )
            return None

        except Exception as exc:
            logger.error(
                "get_storage_lifecycle_policy(%s) unexpected error: %s",
                account_name,
                exc,
            )
            return None

    def get_storage_service_logging(self, resource_group: str, account_name: str, service: str) -> Optional[bool]:
        """Check Azure Monitor diagnostic settings for a storage service sub-resource.

        Three-state return - the calling rule uses strict identity checks
        (is False / is None) to distinguish these states:

            True  - at least one diagnostic setting has StorageRead, StorageWrite,
                    and StorageDelete all enabled (compliant).
            False - no setting covers all three required categories (non-compliant).
            None  - permission error or unexpected SDK failure.
                    Caller must NOT create a finding - skip with a warning
                    to avoid false positives.

        Args:
            resource_group: Resource group containing the storage account.
            account_name:   Name of the storage account.
            service:        Sub-service to check: "blob", "queue", or "table".

        Returns:
            Optional[bool] - True, False, or None as described above.
        """
        _REQUIRED = {"StorageRead", "StorageWrite", "StorageDelete"}
        _SERVICE_MAP = {
            "blob": "blobServices",
            "queue": "queueServices",
            "table": "tableServices",
        }
        svc_path = _SERVICE_MAP.get(service)
        if not svc_path:
            logger.error(
                "get_storage_service_logging: unknown service %r - must be blob, queue, or table",
                service,
            )
            return None

        resource_uri = (
            f"/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.Storage/storageAccounts/{account_name}"
            f"/{svc_path}/default"
        )
        try:
            client = MonitorManagementClient(self.credential, self.subscription_id)
            settings = list(client.diagnostic_settings.list(resource_uri))
            for setting in settings:
                enabled_categories = {
                    log.category for log in (getattr(setting, "logs", None) or []) if getattr(log, "enabled", False)
                }
                if _REQUIRED.issubset(enabled_categories):
                    return True
            return False

        except HttpResponseError as exc:
            logger.error(
                "get_storage_service_logging(%s/%s) HTTP %s - check service principal permissions: %s",
                account_name,
                service,
                exc.status_code,
                exc,
            )
            return None

        except Exception as exc:
            logger.error(
                "get_storage_service_logging(%s/%s) unexpected error: %s",
                account_name,
                service,
                exc,
            )
            return None

    # ------------------------------------------------------------------ #
    # Network                                                               #
    # ------------------------------------------------------------------ #

    def get_network_security_groups(self) -> List[Any]:
        """List all NSGs across all resource groups in the subscription."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return list(client.network_security_groups.list_all())
        except Exception as exc:
            logger.error("get_network_security_groups failed: %s", exc)
            return []

    def get_express_route_ports(self) -> Optional[List[Any]]:
        """List ExpressRoute Direct ports without collapsing API failures.

        An empty list means the subscription has no ExpressRoute Direct ports.
        ``None`` means Azure could not be queried, so callers must preserve an
        indeterminate result and avoid creating findings.
        """
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return list(client.express_route_ports.list())
        except Exception as exc:
            logger.error("get_express_route_ports failed: %s", exc)
            return None

    def get_network_interface(self, resource_group: str, nic_name: str) -> Optional[Any]:
        """Fetch a single NIC by resource group and name."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return client.network_interfaces.get(resource_group, nic_name)
        except Exception as exc:
            logger.error("get_network_interface(%s) failed: %s", nic_name, exc)
            return None

    def get_network_interfaces(self) -> Optional[List[Any]]:
        """List NICs while preserving API failure as indeterminate."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return list(client.network_interfaces.list_all())
        except Exception as exc:
            logger.error("get_network_interfaces failed: %s", exc)
            return None

    def get_route_tables(self) -> Optional[List[Any]]:
        """List route tables while preserving API failure as indeterminate."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return list(client.route_tables.list_all())
        except Exception as exc:
            logger.error("get_route_tables failed: %s", exc)
            return None

    def get_virtual_networks(self) -> List[Any]:
        """List all virtual networks in the subscription."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return list(client.virtual_networks.list_all())
        except Exception as exc:
            logger.error("get_virtual_networks failed: %s", exc)
            return []

    def get_public_ip_addresses(self) -> List[Any]:
        """List all public IP addresses in the subscription."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return list(client.public_ip_addresses.list_all())
        except Exception as exc:
            logger.error("get_public_ip_addresses failed: %s", exc)
            return []

    def get_private_link_inventory(self) -> Optional[List[Dict[str, Any]]]:
        """Collect Private Endpoint state without collapsing API failures.

        The network list operation is authoritative for applicability. A failed
        list returns ``None`` (UNKNOWN); an empty list means NOT_APPLICABLE.
        DNS-zone-group failures are recorded per endpoint as ``None`` so rules
        do not confuse missing permissions with a missing association.
        """
        collected_at = datetime.now(timezone.utc).isoformat()
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            endpoints = list(client.private_endpoints.list_by_subscription())
        except Exception as exc:
            logger.error("get_private_link_inventory failed: %s", exc)
            return None

        inventory: List[Dict[str, Any]] = []
        for endpoint in endpoints:
            endpoint_id = getattr(endpoint, "id", "") or ""
            parsed = self.parse_resource_id(endpoint_id)
            resource_group = parsed.get("resource_group", "")
            endpoint_name = getattr(endpoint, "name", "") or parsed.get("name", "")
            connections = getattr(endpoint, "private_link_service_connections", None) or []
            manual_connections = getattr(endpoint, "manual_private_link_service_connections", None) or []
            connections = [*connections, *manual_connections]

            try:
                zone_groups = list(client.private_dns_zone_groups.list(resource_group, endpoint_name))
                zone_ids = [
                    getattr(config, "private_dns_zone_id", "")
                    for group in zone_groups
                    for config in (getattr(group, "private_dns_zone_configs", None) or [])
                    if getattr(config, "private_dns_zone_id", "")
                ]
            except Exception as exc:
                logger.error("private DNS zone groups unavailable for %s: %s", endpoint_name, exc)
                zone_ids = None

            dns_configs = []
            for config in getattr(endpoint, "custom_dns_configs", None) or []:
                dns_configs.append(
                    {
                        "fqdn": getattr(config, "fqdn", "") or "",
                        "ip_addresses": list(getattr(config, "ip_addresses", None) or []),
                    }
                )

            if not connections:
                inventory.append(
                    {
                        "endpoint_id": endpoint_id,
                        "endpoint_name": endpoint_name,
                        "resource_group": resource_group,
                        "location": getattr(endpoint, "location", "") or "",
                        "target_id": "",
                        "connection_status": None,
                        "dns_zone_ids": zone_ids,
                        "dns_configs": dns_configs,
                        "public_network_access": None,
                        "collected_at": collected_at,
                    }
                )
                continue

            for connection in connections:
                target_id = getattr(connection, "private_link_service_id", "") or ""
                state = getattr(connection, "private_link_service_connection_state", None)
                inventory.append(
                    {
                        "endpoint_id": endpoint_id,
                        "endpoint_name": endpoint_name,
                        "resource_group": resource_group,
                        "location": getattr(endpoint, "location", "") or "",
                        "target_id": target_id,
                        "connection_status": getattr(state, "status", None),
                        "dns_zone_ids": zone_ids,
                        "dns_configs": dns_configs,
                        "public_network_access": self._get_private_link_target_public_access(target_id),
                        "collected_at": collected_at,
                    }
                )
        return inventory

    def _get_private_link_target_public_access(self, resource_id: str) -> Optional[bool]:
        """Return public-access state for supported Private Link PaaS targets."""
        parts = [part for part in (resource_id or "").split("/") if part]
        lowered = [part.lower() for part in parts]
        try:
            rg_index = lowered.index("resourcegroups")
            provider_index = lowered.index("providers")
            resource_group = parts[rg_index + 1]
            provider = lowered[provider_index + 1]
            resource_type = lowered[provider_index + 2]
            name = parts[provider_index + 3]
        except (ValueError, IndexError):
            return None

        try:
            if provider == "microsoft.storage" and resource_type == "storageaccounts":
                resource = StorageManagementClient(
                    self.credential, self.subscription_id
                ).storage_accounts.get_properties(resource_group, name)
            elif provider == "microsoft.keyvault" and resource_type == "vaults":
                resource = KeyVaultManagementClient(self.credential, self.subscription_id).vaults.get(
                    resource_group, name
                )
            elif provider == "microsoft.sql" and resource_type == "servers":
                resource = SqlManagementClient(self.credential, self.subscription_id).servers.get(resource_group, name)
            else:
                return None
            value = getattr(resource, "public_network_access", None)
            if value is None:
                value = getattr(getattr(resource, "properties", None), "public_network_access", None)
            normalized = enum_str(value).lower()
            if normalized in {"enabled", "true", "1"}:
                return True
            if normalized in {"disabled", "false", "0"}:
                return False
            return None
        except Exception as exc:
            logger.error("public network access unavailable for %s: %s", resource_id, exc)
            return None

    def get_critical_paas_inventory(self) -> Dict[str, Optional[List[Dict[str, Any]]]]:
        """Collect public-access state for critical PaaS services independently.

        Each service returns a list on a successful API call (including an
        empty list) or ``None`` on failure. Rules can therefore evaluate
        successful services without treating a denied service as compliant.
        """
        if self._critical_paas_cache is not _UNSET:
            return self._critical_paas_cache

        collected_at = datetime.now(timezone.utc).isoformat()
        collectors = {
            "storage": self._collect_public_storage_accounts,
            "key_vault": self._collect_public_key_vaults,
            "sql": self._collect_public_sql_servers,
            "postgresql": self._collect_public_postgresql_servers,
            "app_service": self._collect_public_web_apps,
        }
        result: Dict[str, Optional[List[Dict[str, Any]]]] = {}
        for service, collector in collectors.items():
            try:
                result[service] = collector(collected_at)
            except Exception as exc:
                logger.error("critical PaaS inventory failed for %s: %s", service, exc)
                result[service] = None
        self._critical_paas_cache = result
        return result

    @staticmethod
    def _public_access_value(resource: Any) -> Optional[bool]:
        value = getattr(resource, "public_network_access", None)
        if value is None:
            value = getattr(getattr(resource, "properties", None), "public_network_access", None)
        normalized = enum_str(value).lower()
        if normalized in {"enabled", "true", "1"}:
            return True
        if normalized in {"disabled", "false", "0"}:
            return False
        return None

    def _paas_record(self, resource: Any, service: str, collected_at: str) -> Dict[str, Any]:
        resource_id = getattr(resource, "id", "") or ""
        parsed = self.parse_resource_id(resource_id)
        return {
            "resource_id": resource_id,
            "resource_name": getattr(resource, "name", "") or parsed.get("name", ""),
            "resource_type": service,
            "resource_group": parsed.get("resource_group", ""),
            "location": getattr(resource, "location", "") or "",
            "public_network_access": self._public_access_value(resource),
            "collected_at": collected_at,
        }

    def _collect_public_storage_accounts(self, collected_at: str) -> List[Dict[str, Any]]:
        resources = StorageManagementClient(self.credential, self.subscription_id).storage_accounts.list()
        return [self._paas_record(item, "Microsoft.Storage/storageAccounts", collected_at) for item in resources]

    def _collect_public_key_vaults(self, collected_at: str) -> List[Dict[str, Any]]:
        resources = KeyVaultManagementClient(self.credential, self.subscription_id).vaults.list_by_subscription()
        return [self._paas_record(item, "Microsoft.KeyVault/vaults", collected_at) for item in resources]

    def _collect_public_sql_servers(self, collected_at: str) -> List[Dict[str, Any]]:
        resources = SqlManagementClient(self.credential, self.subscription_id).servers.list()
        return [self._paas_record(item, "Microsoft.Sql/servers", collected_at) for item in resources]

    def _collect_public_postgresql_servers(self, collected_at: str) -> List[Dict[str, Any]]:
        resources = PostgreSQLManagementClient(self.credential, self.subscription_id).servers.list()
        return [self._paas_record(item, "Microsoft.DBforPostgreSQL/servers", collected_at) for item in resources]

    def _collect_public_web_apps(self, collected_at: str) -> List[Dict[str, Any]]:
        from azure.mgmt.web import WebSiteManagementClient

        resources = WebSiteManagementClient(self.credential, self.subscription_id).web_apps.list()
        return [self._paas_record(item, "Microsoft.Web/sites", collected_at) for item in resources]

    def get_application_gateways(self) -> Optional[List[Any]]:
        """List Application Gateways, preserving API failure as UNKNOWN."""
        if self._application_gateways_cache is not _UNSET:
            return self._application_gateways_cache
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            self._application_gateways_cache = list(client.application_gateways.list_all())
        except Exception as exc:
            logger.error("get_application_gateways failed: %s", exc)
            self._application_gateways_cache = None
        return self._application_gateways_cache

    def get_waf_policies(self) -> Optional[List[Any]]:
        """List regional Application Gateway WAF policies with failure state."""
        if self._waf_policies_cache is not _UNSET:
            return self._waf_policies_cache
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            self._waf_policies_cache = list(client.web_application_firewall_policies.list_all())
        except Exception as exc:
            logger.error("get_waf_policies failed: %s", exc)
            self._waf_policies_cache = None
        return self._waf_policies_cache

    def get_waf_diagnostic_logging(self, resource_id: str, sku_name: str) -> Optional[bool]:
        """Return whether the SKU-supported Application Gateway log categories are enabled."""
        normalized_sku = (sku_name or "").strip().lower()
        if not normalized_sku:
            logger.warning("Application Gateway SKU unavailable for %s", resource_id)
            return None
        required = {"ApplicationGatewayAccessLog", "ApplicationGatewayFirewallLog"}
        # ApplicationGatewayPerformanceLog is exposed by v1 only. v2 publishes
        # performance telemetry through Azure Monitor metrics instead.
        if not normalized_sku.endswith("_v2"):
            required.add("ApplicationGatewayPerformanceLog")
        try:
            client = MonitorManagementClient(self.credential, self.subscription_id)
            settings = list(client.diagnostic_settings.list(resource_id))
            enabled = {
                getattr(log, "category", "")
                for setting in settings
                for log in (getattr(setting, "logs", None) or [])
                if getattr(log, "enabled", False)
            }
            return required.issubset(enabled)
        except Exception as exc:
            logger.error("get_waf_diagnostic_logging failed for %s: %s", resource_id, exc)
            return None

    def get_azure_firewalls(self, resource_group: str) -> List[Any]:
        """List all Azure Firewalls in a resource group."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return list(client.azure_firewalls.list(resource_group))
        except Exception as exc:
            logger.error("get_azure_firewalls(%s) failed: %s", resource_group, exc)
            return []

    def get_all_azure_firewalls(self) -> Optional[List[Any]]:
        """List all Azure Firewalls in the subscription.

        Three-state return - the calling rule distinguishes these states:

            [...] - successful listing (may be empty: genuinely no firewalls).
            None  - listing failed (permissions, network, SDK error). The
                    caller must NOT flag VNets as non-compliant, since it
                    cannot tell which VNets are protected - skip to avoid
                    false positives.
        """
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return list(client.azure_firewalls.list_all())
        except Exception as exc:
            logger.error("get_all_azure_firewalls failed: %s", exc)
            return None

    def get_vnet_peerings(self, resource_group: str, vnet_name: str) -> List[Any]:
        """List all peering connections for a Virtual Network."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return list(client.virtual_network_peerings.list(resource_group, vnet_name))
        except Exception as exc:
            logger.error("get_vnet_peerings(%s) failed: %s", vnet_name, exc)
            return []

    def get_load_balancers(self) -> List[Any]:
        """List all load balancers in the subscription."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return list(client.load_balancers.list_all())
        except Exception as exc:
            logger.error("get_load_balancers failed: %s", exc)
            return []

    def get_dns_zones(self) -> List[Any]:
        """List all DNS zones in the subscription."""
        try:
            from azure.mgmt.dns import DnsManagementClient

            client = DnsManagementClient(self.credential, self.subscription_id)
            return list(client.zones.list())
        except Exception as exc:
            logger.error("get_dns_zones failed: %s", exc)
            return []

    def get_dns_record_sets(self, resource_group: str, zone_name: str) -> List[Any]:
        """List all record sets in a DNS zone."""
        try:
            from azure.mgmt.dns import DnsManagementClient

            client = DnsManagementClient(self.credential, self.subscription_id)
            return list(client.record_sets.list_by_dns_zone(resource_group, zone_name))
        except Exception as exc:
            logger.error("get_dns_record_sets failed for zone %s: %s", zone_name, exc)
            return []

    # ------------------------------------------------------------------ #
    # Kubernetes / AKS                                                     #
    # ------------------------------------------------------------------ #

    def get_managed_clusters(self) -> Optional[List[Any]]:
        """List AKS managed clusters, preserving an indeterminate failure state.

        The result is cached for the lifetime of this client because every AKS
        rule evaluates the same subscription-level collection.

        Returns:
            A list (including an empty list) when Azure responds successfully,
            or ``None`` when permissions, networking, or the SDK prevent the
            collection from being evaluated. Callers must never interpret
            ``None`` as a compliant result.
        """
        if self._managed_clusters_cache is not _UNSET:
            return self._managed_clusters_cache

        try:
            client = ContainerServiceClient(self.credential, self.subscription_id)
            self._managed_clusters_cache = list(client.managed_clusters.list())
        except HttpResponseError as exc:
            logger.error(
                "get_managed_clusters HTTP %s - check Microsoft.ContainerService/managedClusters/read: %s",
                exc.status_code,
                exc,
            )
            self._managed_clusters_cache = None
        except Exception as exc:
            logger.error("get_managed_clusters failed: %s", exc)
            self._managed_clusters_cache = None

        return self._managed_clusters_cache

    # ------------------------------------------------------------------ #
    # Compute                                                               #
    # ------------------------------------------------------------------ #

    def get_virtual_machines(self) -> List[Any]:
        """List all VMs across all resource groups in the subscription."""
        try:
            client = ComputeManagementClient(self.credential, self.subscription_id)
            return list(client.virtual_machines.list_all())
        except Exception as exc:
            logger.error("get_virtual_machines failed: %s", exc)
            return []

    def get_virtual_machine_scale_sets(self) -> List[Any]:
        """List all VM Scale Sets across all resource groups in the subscription."""
        try:
            client = ComputeManagementClient(self.credential, self.subscription_id)
            return list(client.virtual_machine_scale_sets.list_all())
        except Exception as exc:
            logger.error("get_virtual_machine_scale_sets failed: %s", exc)
            return []

    def get_web_apps(self) -> List[Any]:
        """List all App Services in the subscription."""
        try:
            from azure.mgmt.web import WebSiteManagementClient

            client = WebSiteManagementClient(self.credential, self.subscription_id)
            return list(client.web_apps.list())
        except Exception as exc:
            logger.error("get_web_apps failed: %s", exc)
            return []

    def get_jit_network_access_policies(self) -> Optional[List[Any]]:
        """List Microsoft Defender for Cloud Just-In-Time VM access policies.

        Returns a list (including an empty list) when Defender for Cloud responds,
        or ``None`` when permissions, networking, the SDK, or a subscription
        without Defender for Cloud prevent the collection from being evaluated.
        Callers must treat ``None`` as "JIT coverage unknown", never as "no JIT".
        """
        try:
            from azure.mgmt.security import SecurityCenter

            client = SecurityCenter(self.credential, self.subscription_id)
            return list(client.jit_network_access_policies.list())
        except Exception as exc:
            logger.error("get_jit_network_access_policies failed: %s", exc)
            return None

    def get_function_app_security_posture(self) -> Optional[List[Dict[str, Any]]]:
        """Return a cached, secret-free posture for Function Apps."""
        if self._function_apps_cache is not _UNSET:
            return self._function_apps_cache
        try:
            from azure.mgmt.web import WebSiteManagementClient

            client = WebSiteManagementClient(self.credential, self.subscription_id)
            result: List[Dict[str, Any]] = []
            for app in client.web_apps.list():
                if "functionapp" not in str(getattr(app, "kind", "")).lower():
                    continue
                try:
                    parsed = self.parse_resource_id(getattr(app, "id", ""))
                    config = client.web_apps.get_configuration(parsed.get("resource_group", ""), app.name)
                    identity = getattr(app, "identity", None)
                    result.append(
                        {
                            "id": app.id,
                            "name": app.name,
                            "kind": getattr(app, "kind", None),
                            "https_only": getattr(app, "https_only", None),
                            "min_tls_version": getattr(config, "min_tls_version", None),
                            "ftps_state": getattr(config, "ftps_state", None),
                            "remote_debugging_enabled": getattr(config, "remote_debugging_enabled", None),
                            "identity_type": getattr(identity, "type", None) if identity is not None else "None",
                        }
                    )
                except Exception as exc:
                    logger.warning("get_function_app_security_posture: skipping %s: %s", getattr(app, "name", "?"), exc)
            self._function_apps_cache = result
        except Exception as exc:
            logger.error("get_function_app_security_posture failed: %s", exc)
            self._function_apps_cache = None
        return self._function_apps_cache

    def get_private_endpoint_posture(self) -> Optional[List[Dict[str, Any]]]:
        """Return public-access and approved Private Link state for supported PaaS resources."""
        if self._private_endpoint_posture_cache is not _UNSET:
            return self._private_endpoint_posture_cache
        try:
            network = NetworkManagementClient(self.credential, self.subscription_id)
            endpoints = list(network.private_endpoints.list_by_subscription())
            approved: Dict[str, set[str]] = {}
            records: List[Dict[str, Any]] = []
            for endpoint in endpoints:
                endpoint_connections = list(getattr(endpoint, "private_link_service_connections", None) or [])
                endpoint_connections.extend(getattr(endpoint, "manual_private_link_service_connections", None) or [])
                for connection in endpoint_connections:
                    target = str(getattr(connection, "private_link_service_id", "") or "").lower()
                    state = getattr(connection, "private_link_service_connection_state", None)
                    status = str(getattr(state, "status", "") or "")
                    groups = {str(value).lower() for value in (getattr(connection, "group_ids", None) or [])}
                    if target and status.lower() == "approved":
                        approved.setdefault(target, set()).update(groups)
                    elif target and status.lower() in {"pending", "rejected", "disconnected"}:
                        records.append(
                            {"id": endpoint.id, "name": endpoint.name, "service": "connection", "status": status}
                        )

            def add(resource: Any, service: str, public: Any, required: set[str]) -> None:
                rid = str(getattr(resource, "id", "") or "")
                records.append(
                    {
                        "id": rid,
                        "name": getattr(resource, "name", ""),
                        "service": service,
                        "public_network_access": public,
                        "approved_groups": sorted(approved.get(rid.lower(), set())),
                        "required_groups": sorted(required),
                    }
                )

            try:
                for item in StorageManagementClient(self.credential, self.subscription_id).storage_accounts.list():
                    add(item, "storage", getattr(item, "public_network_access", None), {"blob"})
            except Exception as exc:
                logger.warning("Storage account network posture unavailable: %s", exc)
            try:
                for item in SqlManagementClient(self.credential, self.subscription_id).servers.list():
                    add(item, "sql", getattr(item, "public_network_access", None), {"sqlserver"})
            except Exception as exc:
                logger.warning("Azure SQL network posture unavailable: %s", exc)
            try:
                from azure.mgmt.postgresqlflexibleservers import PostgreSQLManagementClient as FlexiblePostgreSQLClient

                for item in FlexiblePostgreSQLClient(self.credential, self.subscription_id).servers.list():
                    add(
                        item,
                        "postgresql",
                        getattr(getattr(item, "network", None), "public_network_access", None),
                        {"postgresqlserver"},
                    )
            except Exception as exc:
                logger.warning("PostgreSQL Flexible Server posture unavailable: %s", exc)
            try:
                from azure.mgmt.web import WebSiteManagementClient

                web = WebSiteManagementClient(self.credential, self.subscription_id)
                for item in web.web_apps.list():
                    try:
                        parsed = self.parse_resource_id(getattr(item, "id", ""))
                        config = web.web_apps.get_configuration(parsed.get("resource_group", ""), item.name)
                        public = getattr(item, "public_network_access", None) or getattr(
                            config, "public_network_access", None
                        )
                        if str(getattr(config, "ip_security_restrictions_default_action", "")).lower() == "deny":
                            public = "Disabled"
                        add(item, "web", public, {"sites"})
                    except Exception as exc:
                        logger.warning(
                            "Web/Function App posture unavailable for %s: %s", getattr(item, "name", "?"), exc
                        )
            except Exception as exc:
                logger.warning("Web/Function App network posture unavailable: %s", exc)
            try:
                from azure.mgmt.recoveryservices import RecoveryServicesClient

                for item in RecoveryServicesClient(
                    self.credential, self.subscription_id
                ).vaults.list_by_subscription_id():
                    add(
                        item,
                        "recovery",
                        getattr(getattr(item, "properties", None), "public_network_access", None),
                        {"azurebackup"},
                    )
            except Exception as exc:
                logger.warning("Recovery Services network posture unavailable: %s", exc)
            self._private_endpoint_posture_cache = records
        except Exception as exc:
            logger.error("get_private_endpoint_posture failed: %s", exc)
            self._private_endpoint_posture_cache = None
        return self._private_endpoint_posture_cache

    def get_recovery_vault_security_posture(self) -> Optional[List[Dict[str, Any]]]:
        """Return cached Recovery Services security settings without backup contents."""
        if self._recovery_vaults_cache is not _UNSET:
            return self._recovery_vaults_cache
        try:
            from azure.mgmt.recoveryservices import RecoveryServicesClient

            result: List[Dict[str, Any]] = []
            for vault in RecoveryServicesClient(self.credential, self.subscription_id).vaults.list_by_subscription_id():
                props = getattr(vault, "properties", None)
                security = getattr(props, "security_settings", None)
                soft = getattr(security, "soft_delete_settings", None)
                immutable = getattr(security, "immutability_settings", None)
                monitoring = getattr(props, "monitoring_settings", None)
                monitor_alerts = getattr(monitoring, "azure_monitor_alert_settings", None)
                result.append(
                    {
                        "id": vault.id,
                        "name": vault.name,
                        "soft_delete_state": getattr(soft, "soft_delete_state", None),
                        "soft_delete_retention_days": getattr(soft, "soft_delete_retention_period_in_days", None),
                        "immutability_state": getattr(immutable, "state", None),
                        "multi_user_authorization": getattr(security, "multi_user_authorization", None),
                        "resource_guard_operations": getattr(props, "resource_guard_operation_requests", None),
                        "monitoring_alerts_for_job_failures": getattr(
                            monitor_alerts, "alerts_for_all_job_failures", None
                        ),
                    }
                )
            self._recovery_vaults_cache = result
        except Exception as exc:
            logger.error("get_recovery_vault_security_posture failed: %s", exc)
            self._recovery_vaults_cache = None
        return self._recovery_vaults_cache

    def get_vm_extensions(self, resource_group: str, vm_name: str) -> Optional[List[Any]]:
        """List all extensions installed on a virtual machine."""
        try:
            result = ComputeManagementClient(self.credential, self.subscription_id).virtual_machine_extensions.list(
                resource_group, vm_name
            )
            return list(getattr(result, "value", []) or [])
        except Exception as exc:
            logger.error("get_vm_extensions failed for %s/%s: %s", resource_group, vm_name, exc)
            return None

    def get_disk(self, disk_id: str) -> Optional[Any]:
        """Resolve the Disk resource referenced by a VM's ManagedDiskParameters.

        ManagedDiskParameters (the object embedded in a VM's storage_profile)
        only carries id, storage_account_type, disk_encryption_set and
        security_profile — the encryption state lives on the underlying Disk
        resource and must be fetched separately. Cached per subscription
        (this client instance already scopes one subscription) because the
        same disk may be evaluated more than once during a scan.

        Returns:
            The Disk resource, or ``None`` when the ID is missing/malformed
            or Azure cannot return it (permissions, deletion, SDK error).
            Callers must never interpret ``None`` as a compliant result.
        """
        if not disk_id:
            return None
        if disk_id in self._disks_cache:
            return self._disks_cache[disk_id]

        disk = None
        try:
            parsed = self.parse_resource_id(disk_id)
            resource_group = parsed.get("resource_group", "")
            disk_name = parsed.get("name", "")
            if resource_group and disk_name:
                client = ComputeManagementClient(self.credential, self.subscription_id)
                disk = client.disks.get(resource_group, disk_name)
            else:
                logger.error("get_disk failed: could not parse resource group/name from %s", disk_id)
        except Exception as exc:
            logger.error("get_disk failed for %s: %s", disk_id, exc)
            disk = None

        self._disks_cache[disk_id] = disk
        return disk

    # ------------------------------------------------------------------ #
    # Databases                                                             #
    # ------------------------------------------------------------------ #

    def get_postgresql_servers(self) -> List[Any]:
        """List all PostgreSQL single-server instances in the subscription."""
        try:
            client = PostgreSQLManagementClient(self.credential, self.subscription_id)
            return list(client.servers.list())
        except Exception as exc:
            logger.error("get_postgresql_servers failed: %s", exc)
            return []

    def get_sql_servers(self) -> List[Any]:
        """List all Azure SQL servers in the subscription."""
        try:
            client = SqlManagementClient(self.credential, self.subscription_id)
            return list(client.servers.list())
        except Exception as exc:
            logger.error("get_sql_servers failed: %s", exc)
            return []

    def get_sql_server_auditing_policy(self, resource_group: str, server_name: str) -> Optional[Any]:
        """Fetch the blob auditing policy for an Azure SQL server."""
        try:
            client = SqlManagementClient(self.credential, self.subscription_id)
            return client.server_blob_auditing_policies.get(resource_group, server_name)
        except ResourceNotFoundError:
            return False
        except Exception as exc:
            logger.error("get_sql_server_auditing_policy(%s) failed: %s", server_name, exc)
            return None

    def get_sql_server_azure_ad_only_authentication(self, resource_group: str, server_name: str) -> Optional[bool]:
        """Return whether Microsoft Entra-only authentication is enabled.

        The setting is a child resource and is not populated on objects from
        ``servers.list()``. ``False`` represents a confirmed absent/disabled
        configuration; ``None`` preserves an indeterminate API failure.
        """
        try:
            client = SqlManagementClient(self.credential, self.subscription_id)
            authentication = client.server_azure_ad_only_authentications.get(resource_group, server_name, "Default")
            return bool(getattr(authentication, "azure_ad_only_authentication", False))
        except ResourceNotFoundError:
            return False
        except Exception as exc:
            logger.error(
                "get_sql_server_azure_ad_only_authentication(%s) failed: %s",
                server_name,
                exc,
            )
            return None

    def get_sql_server_firewall_rules(self, resource_group: str, server_name: str) -> List[Any]:
        """List all firewall rules for an Azure SQL server."""
        try:
            client = SqlManagementClient(self.credential, self.subscription_id)
            return list(client.firewall_rules.list_by_server(resource_group, server_name))
        except Exception as exc:
            logger.error("get_sql_server_firewall_rules(%s) failed: %s", server_name, exc)
            return []

    def get_sql_server_vulnerability_assessment(self, resource_group: str, server_name: str) -> Optional[Any]:
        """Fetch the default vulnerability-assessment configuration for a SQL server."""
        try:
            client = SqlManagementClient(self.credential, self.subscription_id)
            return client.server_vulnerability_assessments.get(resource_group, server_name, "default")
        except ResourceNotFoundError:
            return False
        except Exception as exc:
            logger.error("get_sql_server_vulnerability_assessment(%s) failed: %s", server_name, exc)
            return None

    def get_cosmos_accounts(self) -> Optional[List[Any]]:
        """List Cosmos DB accounts, if the optional management SDK is available."""
        try:
            from azure.mgmt.cosmosdb import CosmosDBManagementClient

            client = CosmosDBManagementClient(self.credential, self.subscription_id)
            return list(client.database_accounts.list())
        except Exception as exc:
            logger.error("get_cosmos_accounts failed: %s", exc)
            return None

    def get_managed_caches(self) -> Optional[List[Any]]:
        """List Azure Managed Redis/Cache accounts, if the SDK is available."""
        try:
            from azure.mgmt.redis import RedisManagementClient

            client = RedisManagementClient(self.credential, self.subscription_id)
            return list(client.redis.list())
        except Exception as exc:
            logger.error("get_managed_caches failed: %s", exc)
            return None

    # ------------------------------------------------------------------ #
    # Key Vault                                                             #
    # ------------------------------------------------------------------ #

    def get_key_vaults(self) -> List[Any]:
        """List all Key Vaults in the subscription with full properties."""
        try:
            client = KeyVaultManagementClient(self.credential, self.subscription_id)
            return list(client.vaults.list_by_subscription())
        except Exception as exc:
            logger.error("get_key_vaults failed: %s", exc)
            return []

    def get_key_vault_certificates(self, vault_name: str) -> List[Any]:
        """List all certificates in a Key Vault using the Key Vault data plane API."""
        try:
            from azure.keyvault.certificates import CertificateClient

            vault_url = f"https://{vault_name}.vault.azure.net"
            client = CertificateClient(vault_url=vault_url, credential=self.credential)
            return list(client.list_properties_of_certificates())
        except Exception as exc:
            logger.error("get_key_vault_certificates(%s) failed: %s", vault_name, exc)
            return []

    def get_key_vault_keys(self, vault_name: str) -> List[Any]:
        """List all keys in a Key Vault using the Key Vault data plane API."""
        try:
            from azure.keyvault.keys import KeyClient

            vault_url = f"https://{vault_name}.vault.azure.net"
            client = KeyClient(vault_url=vault_url, credential=self.credential)
            return list(client.list_properties_of_keys())
        except Exception as exc:
            logger.error("get_key_vault_keys(%s) failed: %s", vault_name, exc)
            return []

    # ------------------------------------------------------------------ #
    # Monitoring                                                            #
    # ------------------------------------------------------------------ #

    def get_diagnostic_settings(self, resource_id: str) -> Optional[bool]:
        """Return diagnostic logging status for a resource.

        Three-state return:

            True  - at least one diagnostic log category is enabled.
            False - no diagnostic settings exist or all logs are disabled.
            None  - unable to determine status due to permissions/API failure.

        Returns:
            Optional[bool] - True, False, or None as described above.
        """
        try:
            client = MonitorManagementClient(
                self.credential,
                self.subscription_id,
            )
            settings = list(client.diagnostic_settings.list(resource_id))
            if not settings:
                return False
            for setting in settings:
                logs = getattr(setting, "logs", [])
                for log in logs:
                    category = getattr(log, "category", "")
                    enabled = getattr(log, "enabled", False)
                    if category == "AuditEvent" and enabled:
                        return True
            return False

        except HttpResponseError as exc:
            logger.error(
                "get_diagnostic_settings(%s) HTTP %s: %s",
                resource_id,
                exc.status_code,
                exc,
            )
            return None

        except Exception as exc:
            logger.error(
                "get_diagnostic_settings(%s) failed: %s",
                resource_id,
                exc,
            )
            return None

    # ------------------------------------------------------------------ #
    # Identity / Authorization                                              #
    # ------------------------------------------------------------------ #

    def _get_graph_collection(self, url: str, operation: str) -> Optional[List[Dict[str, Any]]]:
        """Fetch a paginated Microsoft Graph collection or return ``None`` on failure."""
        import requests

        items: List[Dict[str, Any]] = []
        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {
                "Authorization": f"Bearer {token.token}",
                "ConsistencyLevel": "eventual",
            }
            while url:
                response = requests.get(url, headers=headers, timeout=30)
                response.raise_for_status()
                data = response.json()
                items.extend(data.get("value", []))
                url = data.get("@odata.nextLink", "")
            return items
        except Exception as exc:
            logger.error("%s failed: %s", operation, exc)
            return None

    def get_applications(self) -> Optional[List[Dict[str, Any]]]:
        """Return cached App Registrations with security-relevant properties and owner IDs."""
        if self._applications_cache is _UNSET:
            select = (
                "id,displayName,appId,signInAudience,passwordCredentials,keyCredentials,"
                "web,spa,publicClient,servicePrincipalLockConfiguration"
            )
            url = f"https://graph.microsoft.com/v1.0/applications?$select={select}&$expand=owners($select=id)&$top=100"
            self._applications_cache = self._get_graph_collection(url, "get_applications")
        return self._applications_cache

    def get_managed_identity_service_principals(self) -> Optional[List[Dict[str, Any]]]:
        """Return cached Microsoft Entra service principals representing managed identities."""
        if self._managed_identity_principals_cache is _UNSET:
            url = (
                "https://graph.microsoft.com/v1.0/servicePrincipals"
                "?$filter=servicePrincipalType eq 'ManagedIdentity'"
                "&$select=id,displayName,servicePrincipalType&$count=true&$top=100"
            )
            self._managed_identity_principals_cache = self._get_graph_collection(
                url,
                "get_managed_identity_service_principals",
            )
        return self._managed_identity_principals_cache

    def get_subscription_role_assignments(self) -> Optional[List[Any]]:
        """Return cached subscription-scope RBAC assignments, preserving API failure as ``None``."""
        if self._subscription_role_assignments_cache is not _UNSET:
            return self._subscription_role_assignments_cache
        try:
            client = AuthorizationManagementClient(self.credential, self.subscription_id)
            scope = f"/subscriptions/{self.subscription_id}"
            self._subscription_role_assignments_cache = list(client.role_assignments.list_for_scope(scope))
        except Exception as exc:
            logger.error("get_subscription_role_assignments failed: %s", exc)
            self._subscription_role_assignments_cache = None
        return self._subscription_role_assignments_cache

    def get_service_principals(self) -> List[Any]:
        """Return role assignments whose principal type is ServicePrincipal."""
        assignments = self.get_subscription_role_assignments()
        if assignments is None:
            return []
        return [a for a in assignments if getattr(a, "principal_type", "") == "ServicePrincipal"]

    def get_postgresql_flexible_servers(self) -> List[Any]:
        """List all PostgreSQL Flexible Server instances in the subscription."""
        try:
            from azure.mgmt.postgresqlflexibleservers import PostgreSQLManagementClient as FlexClient

            client = FlexClient(self.credential, self.subscription_id)
            return list(client.servers.list())
        except Exception as exc:
            logger.error("get_postgresql_flexible_servers failed: %s", exc)
            return []

    def get_postgresql_flexible_server_parameters(self, resource_group: str, server_name: str) -> List[Any]:
        """List all configuration parameters for a PostgreSQL Flexible Server."""
        try:
            from azure.mgmt.postgresqlflexibleservers import PostgreSQLManagementClient as FlexClient

            client = FlexClient(self.credential, self.subscription_id)
            return list(client.configurations.list_by_server(resource_group, server_name))
        except Exception as exc:
            logger.error(
                "get_postgresql_flexible_server_parameters(%s) failed: %s",
                server_name,
                exc,
            )
            return []

    def get_conditional_access_policies(self) -> List[Any]:
        """Fetch Conditional Access policies from the Microsoft Graph API.

        Requires the credential to have 'Policy.Read.All' Graph permission.
        Follows '@odata.nextLink' until exhausted so tenants with enough
        policies to span multiple pages don't silently lose results from
        page 2 onward. Returns empty list if the permission is not granted
        or the call fails.
        """
        import requests  # imported here to keep azure-only paths dependency-free

        policies: List[Any] = []
        url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}

            while url:
                response = requests.get(url, headers=headers, timeout=30)
                response.raise_for_status()
                data = response.json()
                policies.extend(data.get("value", []))
                url = data.get("@odata.nextLink")

            return policies
        except Exception as exc:
            logger.error("get_conditional_access_policies failed: %s", exc)
            return []

    def get_regions_with_resources(self) -> List[str]:
        """List all regions that have at least one resource deployed."""
        try:
            from azure.mgmt.resource import ResourceManagementClient

            client = ResourceManagementClient(self.credential, self.subscription_id)
            regions = {r.location.lower().replace(" ", "") for r in client.resources.list() if r.location}
            return list(regions)
        except Exception as exc:
            logger.error("get_regions_with_resources failed: %s", exc)
            return []

    def get_network_watcher_regions(self) -> List[str]:
        """List all regions that already have Network Watcher enabled."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            regions = {w.location.lower().replace(" ", "") for w in client.network_watchers.list_all() if w.location}
            return list(regions)
        except Exception as exc:
            logger.error("get_network_watcher_regions failed: %s", exc)
            return []

    def get_flow_logs(self) -> Dict[str, Optional[List[Any]]]:
        """Return Network Watcher flow log configurations, keyed by normalized region.

        Flow logs (both legacy NSG-scoped and current VNet-scoped) are only
        listable per-region Network Watcher, never in one subscription-wide
        call, so a failure enumerating or querying one region's watcher must
        not discard - or fabricate absence for - flow logs in a different
        region.

        Returns:
            A dict from normalized region name to that region's list of
            FlowLog resources, or ``None`` when that specific region's
            watcher/flow-log listing failed. A region simply absent from the
            dict means no Network Watcher was found there. Callers must treat
            both ``None`` and a missing key as indeterminate, never as
            "no flow log configured".
        """
        result: Dict[str, Optional[List[Any]]] = {}
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            watchers = list(client.network_watchers.list_all())
        except Exception as exc:
            logger.error("get_flow_logs failed to list network watchers: %s", exc)
            return result

        for watcher in watchers:
            location = (getattr(watcher, "location", "") or "").lower().replace(" ", "")
            watcher_id = getattr(watcher, "id", "") or ""
            parsed = self.parse_resource_id(watcher_id)
            watcher_rg = parsed.get("resource_group", "")
            watcher_name = getattr(watcher, "name", "")
            if not location or not watcher_rg or not watcher_name:
                continue
            try:
                result[location] = list(client.flow_logs.list(watcher_rg, watcher_name))
            except Exception as exc:
                logger.error("get_flow_logs failed for watcher %s/%s: %s", watcher_rg, watcher_name, exc)
                result[location] = None
        return result

    # ------------------------------------------------------------------ #
    # Supply chain: Container Registry, IaC state                          #
    # ------------------------------------------------------------------ #

    def get_container_registries(self) -> Optional[List[Any]]:
        """List Azure Container Registries, preserving an indeterminate failure state.

        Cached for the lifetime of this client because all AZ-SC container
        registry rules evaluate the same subscription-level collection.

        Returns:
            A list (including an empty list) when Azure responds successfully,
            or ``None`` when permissions, networking, or the SDK prevent the
            collection from being evaluated. Callers must never interpret
            ``None`` as a compliant result.
        """
        if self._container_registries_cache is not _UNSET:
            return self._container_registries_cache

        try:
            from azure.mgmt.containerregistry import ContainerRegistryManagementClient

            client = ContainerRegistryManagementClient(self.credential, self.subscription_id)
            self._container_registries_cache = list(client.registries.list())
        except Exception as exc:
            logger.error("get_container_registries failed: %s", exc)
            self._container_registries_cache = None
        return self._container_registries_cache

    def get_blob_containers(self, resource_group: str, account_name: str) -> Optional[List[Any]]:
        """List blob containers for a storage account, including per-container access level.

        Not cached: unlike the subscription-wide collections above, this is
        called once per storage account rather than once per scan.

        Returns:
            A list of container items, or ``None`` when the call fails
            (permissions, throttling, storage account not found).
        """
        try:
            client = StorageManagementClient(self.credential, self.subscription_id)
            return list(client.blob_containers.list(resource_group, account_name))
        except Exception as exc:
            logger.error(
                "get_blob_containers(%s/%s) failed: %s",
                resource_group,
                account_name,
                exc,
            )
            return None

    def get_blob_service_properties(self, resource_group: str, account_name: str) -> Optional[Any]:
        """Return account-wide blob service properties (versioning, soft-delete retention).

        Not cached, for the same reason as get_blob_containers above.

        Returns:
            A BlobServiceProperties object, or ``None`` when the call fails.
        """
        try:
            client = StorageManagementClient(self.credential, self.subscription_id)
            return client.blob_services.get_service_properties(resource_group, account_name)
        except Exception as exc:
            logger.error(
                "get_blob_service_properties(%s/%s) failed: %s",
                resource_group,
                account_name,
                exc,
            )
            return None

    # ------------------------------------------------------------------ #
    # Privileged Access & Identity (issue #258)                            #
    # ------------------------------------------------------------------ #

    def get_privileged_role_members(self) -> Optional[List[Dict[str, Any]]]:
        """Return users assigned to top privileged directory roles.

        Each item: {userId, userDisplayName, userPrincipalName, accountEnabled,
                    lastSignInDateTime, roleId, roleName}

        Requires RoleManagement.Read.Directory and AuditLog.Read.All.
        Returns None on permission failure so rules return no findings.
        """
        _PRIVILEGED_ROLE_IDS = {
            "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
            "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
            "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
            "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
            "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
        }
        url = (
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
            "?$expand=principal($select=id,displayName,userPrincipalName,accountEnabled,signInActivity)"
            "&$filter=roleDefinitionId ne null&$top=100"
        )
        raw = self._get_graph_collection(url, "get_privileged_role_members")
        if raw is None:
            return None
        members = []
        for assignment in raw:
            role_def_id = (assignment.get("roleDefinitionId") or "").split("/")[-1].lower()
            role_name = _PRIVILEGED_ROLE_IDS.get(role_def_id)
            if not role_name:
                continue
            principal = assignment.get("principal") or {}
            user_id = principal.get("id") or assignment.get("principalId", "")
            if not user_id:
                continue
            sign_in = principal.get("signInActivity") or {}
            members.append(
                {
                    "userId": user_id,
                    "userDisplayName": principal.get("displayName", user_id),
                    "userPrincipalName": principal.get("userPrincipalName", ""),
                    "accountEnabled": principal.get("accountEnabled", True),
                    "lastSignInDateTime": sign_in.get("lastSignInDateTime"),
                    "roleId": role_def_id,
                    "roleName": role_name,
                }
            )
        return members

    def get_privileged_users_mfa_methods(self) -> Optional[List[Dict[str, Any]]]:
        """Return authentication method types registered for admin users.

        Each item: {userId, userDisplayName, userPrincipalName, authMethodTypes: [...]}

        Requires UserAuthenticationMethod.Read.All.
        Returns None on permission failure.
        """
        url = (
            "https://graph.microsoft.com/v1.0/reports/authenticationMethods"
            "/userRegistrationDetails?$filter=isAdmin eq true&$top=100"
        )
        raw = self._get_graph_collection(url, "get_privileged_users_mfa_methods")
        if raw is None:
            return None
        return [
            {
                "userId": item.get("id", ""),
                "userDisplayName": item.get("userDisplayName", item.get("userPrincipalName", "")),
                "userPrincipalName": item.get("userPrincipalName", ""),
                "authMethodTypes": item.get("methodsRegistered") or [],
            }
            for item in raw
        ]

    def get_pim_role_assignments(self) -> Optional[List[Dict[str, Any]]]:
        """Return PIM eligible and active role assignment schedules.

        Queries both roleAssignmentSchedules (Active assignments) and
        roleEligibilitySchedules (Eligible assignments) and combines them.

        Each item: {principalId, principalType, roleId, assignmentType} where
        assignmentType is 'Active' or 'Eligible' and principalType is one of
        'user', 'group', or 'servicePrincipal'.

        Requires RoleManagement.Read.Directory.
        Returns None on permission failure.
        """
        results = []
        active_url = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules?$top=100"
        active_raw = self._get_graph_collection(active_url, "get_pim_role_assignments/active")
        if active_raw is None:
            return None
        for item in active_raw:
            role_def_id = (item.get("roleDefinitionId") or "").split("/")[-1].lower()
            results.append(
                {
                    "principalId": item.get("principalId", ""),
                    "principalType": item.get("principalType", "user"),
                    "roleId": role_def_id,
                    "assignmentType": "Active",
                }
            )
        eligible_url = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$top=100"
        eligible_raw = self._get_graph_collection(eligible_url, "get_pim_role_assignments/eligible")
        if eligible_raw is None:
            return None
        for item in eligible_raw:
            role_def_id = (item.get("roleDefinitionId") or "").split("/")[-1].lower()
            results.append(
                {
                    "principalId": item.get("principalId", ""),
                    "principalType": item.get("principalType", "user"),
                    "roleId": role_def_id,
                    "assignmentType": "Eligible",
                }
            )
        return results

    def get_identity_protection_policies(self) -> Optional[Dict[str, Any]]:
        """Detect risk-based protection via Conditional Access risk conditions.

        Rather than querying the unreliable identityProtection/policies endpoints,
        this method inspects Conditional Access policies for risk-based conditions,
        which is the recommended approach for modern tenants.

        Returns dict with keys: userRiskPolicy, signInRiskPolicy — each {isEnabled: bool}.
        Returns None on permission failure.
        """
        policies = self.get_conditional_access_policies()
        if policies is None:
            return None
        user_risk_covered = any(
            p.get("state") == "enabled" and (p.get("conditions") or {}).get("userRiskLevels") for p in policies
        )
        sign_in_risk_covered = any(
            p.get("state") == "enabled" and (p.get("conditions") or {}).get("signInRiskLevels") for p in policies
        )
        return {
            "userRiskPolicy": {"isEnabled": user_risk_covered},
            "signInRiskPolicy": {"isEnabled": sign_in_risk_covered},
        }

    def get_privileged_groups(self) -> Optional[List[Dict[str, Any]]]:
        """Return Entra ID groups that are assignable to directory roles.

        Each item: {id, displayName, ownerCount}

        Requires GroupMember.Read.All and RoleManagement.Read.Directory.
        Returns None on permission failure.
        """
        url = (
            "https://graph.microsoft.com/v1.0/groups"
            "?$filter=isAssignableToRole eq true"
            "&$select=id,displayName&$expand=owners($select=id)&$top=100"
        )
        raw = self._get_graph_collection(url, "get_privileged_groups")
        if raw is None:
            return None
        return [
            {
                "id": grp.get("id", ""),
                "displayName": grp.get("displayName", ""),
                "ownerCount": len(grp.get("owners") or []),
            }
            for grp in raw
            if grp.get("id")
        ]
