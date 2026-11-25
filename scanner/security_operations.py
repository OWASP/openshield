"""Read-only collection foundation for enterprise security-operations controls."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Generic, Mapping, Sequence, TypeVar

from azure.mgmt.monitor import MonitorManagementClient

logger = logging.getLogger(__name__)

T = TypeVar("T")


def workspace_resource_group(workspace: Any) -> str:
    """Extract the resource group name from a Log Analytics workspace's ARM resource ID.

    Shared, module-level helper (not collector-private) so rule modules can
    compute the same per-workspace scope key used internally by the
    Sentinel collection methods without reaching into a private attribute.
    """
    resource_id = str(getattr(workspace, "id", "") or "")
    parts = resource_id.split("/")
    try:
        idx = [p.lower() for p in parts].index("resourcegroups")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return ""


def workspace_scope_key(workspace: Any) -> str:
    """Return the "resource_group/workspace_name" key used to index per-workspace collections."""
    resource_group = workspace_resource_group(workspace)
    workspace_name = str(getattr(workspace, "name", "") or "")
    return f"{resource_group}/{workspace_name}"


def arm_resource_inventory(credential: Any, subscription_id: str) -> Callable[[], Sequence[Any]]:
    """Build a resource_inventory callable backed by the generic ARM resource list.

    ``SecurityOperationsCollector.critical_resource_ids`` needs a callable
    returning every resource in the subscription (id + type only). No
    AzureClient method returns a generic, subscription-wide inventory, so
    this uses azure-mgmt-resource directly.
    """

    def _list() -> Sequence[Any]:
        from azure.mgmt.resource import ResourceManagementClient

        client = ResourceManagementClient(credential, subscription_id)
        return list(client.resources.list())

    return _list


class CollectionStatus(str, Enum):
    """Whether a collector produced authoritative evidence.

    COMPLETE and FAILED are the original, subscription-wide outcomes: either
    the whole collection succeeded (possibly with zero items) or it could not
    be attempted/finished at all. PARTIAL is additive and only used by
    collectors that fan out across multiple independent scopes (for example
    one Sentinel onboarding check per Log Analytics workspace): some scopes
    produced evidence while others did not. Rules must treat PARTIAL like
    COMPLETE for the scopes present in ``items`` and treat the scopes listed
    in ``failed_scopes`` the same way they treat a FAILED collector — as
    UNKNOWN, never as a compliant or non-compliant result.
    """

    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


@dataclass(frozen=True)
class CollectionResult(Generic[T]):
    """Explicit collector result; an API failure is never an empty inventory."""

    status: CollectionStatus
    items: tuple[T, ...]
    source: str
    error_code: str | None = None
    failed_scopes: tuple[str, ...] = dataclass_field(default_factory=tuple)

    @classmethod
    def complete(cls, items: Sequence[T], source: str) -> CollectionResult[T]:
        return cls(CollectionStatus.COMPLETE, tuple(items), source)

    @classmethod
    def failed(cls, source: str, error_code: str = "COLLECTION_FAILED") -> CollectionResult[T]:
        return cls(CollectionStatus.FAILED, (), source, error_code)

    @classmethod
    def partial(
        cls,
        items: Sequence[T],
        source: str,
        failed_scopes: Sequence[str],
        error_code: str = "PARTIAL_COLLECTION",
    ) -> CollectionResult[T]:
        return cls(CollectionStatus.PARTIAL, tuple(items), source, error_code, tuple(failed_scopes))


@dataclass(frozen=True)
class SecurityOperationsPolicy:
    """Organisation-owned inputs required before evaluating issue #262 rules."""

    critical_resource_types: frozenset[str]
    approved_destination_ids: frozenset[str]
    required_activity_categories: frozenset[str]
    minimum_retention_days: int
    required_defender_plans: frozenset[str]
    defender_recommendation_sla_days: int
    required_sentinel_connectors: frozenset[str]
    required_high_severity_analytics: tuple[str, ...]
    approved_exclusions: frozenset[str]


_POLICY_FIELDS = {
    "critical_resource_types",
    "approved_destination_ids",
    "required_activity_categories",
    "minimum_retention_days",
    "required_defender_plans",
    "defender_recommendation_sla_days",
    "required_sentinel_connectors",
    "required_high_severity_analytics",
    "approved_exclusions",
}


def load_security_operations_policy(path: str | Path) -> SecurityOperationsPolicy:
    """Load a strict policy file without silently inventing enterprise defaults."""
    with Path(path).open(encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict) or set(raw) != _POLICY_FIELDS:
        raise ValueError("security-operations policy has missing or unsupported fields")

    list_fields = _POLICY_FIELDS - {"minimum_retention_days", "defender_recommendation_sla_days"}
    for field in list_fields:
        values = raw[field]
        if not isinstance(values, list) or any(not isinstance(value, str) or not value.strip() for value in values):
            raise ValueError(f"{field} must be a list of non-empty strings")
    for field in ("minimum_retention_days", "defender_recommendation_sla_days"):
        if not isinstance(raw[field], int) or isinstance(raw[field], bool) or raw[field] <= 0:
            raise ValueError(f"{field} must be a positive integer")

    normalised = {field: frozenset(value.strip().lower() for value in raw[field]) for field in list_fields}
    return SecurityOperationsPolicy(
        critical_resource_types=normalised["critical_resource_types"],
        approved_destination_ids=normalised["approved_destination_ids"],
        required_activity_categories=normalised["required_activity_categories"],
        minimum_retention_days=raw["minimum_retention_days"],
        required_defender_plans=normalised["required_defender_plans"],
        defender_recommendation_sla_days=raw["defender_recommendation_sla_days"],
        required_sentinel_connectors=normalised["required_sentinel_connectors"],
        required_high_severity_analytics=tuple(value.strip() for value in raw["required_high_severity_analytics"]),
        approved_exclusions=normalised["approved_exclusions"],
    )


class SecurityOperationsCollector:
    """Collect Azure Monitor configuration without reading log content."""

    def __init__(
        self,
        credential: Any,
        subscription_id: str,
        *,
        monitor_client: Any | None = None,
        resource_inventory: Callable[[], Sequence[Any]] | None = None,
        security_client: Any | None = None,
        log_analytics_client: Any | None = None,
        sentinel_client_factory: Callable[[str], Any] | None = None,
    ) -> None:
        self.monitor = monitor_client or MonitorManagementClient(credential, subscription_id)
        self.resource_inventory = resource_inventory
        self._credential = credential
        self._subscription_id = subscription_id
        self._security_client = security_client
        self._log_analytics_client = log_analytics_client
        self._sentinel_client_factory = sentinel_client_factory
        self._sentinel_client_cache: dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    # Lazily constructed SDK clients (never built until first use, so a  #
    # test double supplied via the constructor is always preferred).    #
    # ------------------------------------------------------------------ #

    @property
    def security(self) -> Any:
        if self._security_client is None:
            from azure.mgmt.security import SecurityCenter

            self._security_client = SecurityCenter(self._credential, self._subscription_id)
        return self._security_client

    @property
    def log_analytics(self) -> Any:
        if self._log_analytics_client is None:
            from azure.mgmt.loganalytics import LogAnalyticsManagementClient

            self._log_analytics_client = LogAnalyticsManagementClient(self._credential, self._subscription_id)
        return self._log_analytics_client

    def _sentinel_client(self, resource_group: str) -> Any:
        """Return a Sentinel client for ``resource_group``, honouring an injected factory.

        Microsoft Sentinel's SDK client is not subscription-wide: every
        operation takes a resource group and workspace name. Tests provide a
        ``sentinel_client_factory`` callable; production code builds one
        ``SecurityInsights`` client per resource group and reuses it.
        """
        if self._sentinel_client_factory is not None:
            return self._sentinel_client_factory(resource_group)
        if resource_group not in self._sentinel_client_cache:
            from azure.mgmt.securityinsight import SecurityInsights

            self._sentinel_client_cache[resource_group] = SecurityInsights(self._credential, self._subscription_id)
        return self._sentinel_client_cache[resource_group]

    def subscription_diagnostic_settings(self) -> CollectionResult[Any]:
        source = "Microsoft.Insights/subscriptionDiagnosticSettings"
        try:
            return CollectionResult.complete(list(self.monitor.subscription_diagnostic_settings.list()), source)
        except Exception:
            return CollectionResult.failed(source)

    def resource_diagnostic_settings(
        self, resource_ids: Sequence[str]
    ) -> CollectionResult[Mapping[str, tuple[Any, ...]]]:
        source = "Microsoft.Insights/diagnosticSettings"
        collected: dict[str, tuple[Any, ...]] = {}
        try:
            for resource_id in resource_ids:
                if not isinstance(resource_id, str) or not resource_id.strip():
                    raise ValueError("resource IDs must be non-empty strings")
                collected[resource_id] = tuple(self.monitor.diagnostic_settings.list(resource_id))
            return CollectionResult.complete((collected,), source)
        except Exception:
            return CollectionResult.failed(source)

    def critical_resource_ids(self, policy: SecurityOperationsPolicy) -> CollectionResult[str]:
        source = "Azure resource inventory"
        if self.resource_inventory is None:
            return CollectionResult.failed(source, "INVENTORY_NOT_CONFIGURED")
        try:
            resources = self.resource_inventory()
            ids = []
            for resource in resources:
                resource_id = str(getattr(resource, "id", "") or "").strip()
                resource_type = str(getattr(resource, "type", "") or "").strip().lower()
                if resource_id and resource_type in policy.critical_resource_types:
                    ids.append(resource_id)
            return CollectionResult.complete(ids, source)
        except Exception:
            return CollectionResult.failed(source)

    # ------------------------------------------------------------------ #
    # Defender for Cloud (controls 6-7)                                  #
    # ------------------------------------------------------------------ #

    def defender_pricings(self) -> CollectionResult[Any]:
        """Collect Defender for Cloud plan pricing/enablement at subscription scope.

        ``pricings.list`` returns a non-paginated ``PricingList`` wrapper
        (``.value``), not an iterable of ``Pricing`` directly, unlike most
        other list operations used by this collector.
        """
        source = "Microsoft.Security/pricings"
        scope_id = f"/subscriptions/{self._subscription_id}"
        try:
            response = self.security.pricings.list(scope_id)
            items = list(getattr(response, "value", response) or [])
            return CollectionResult.complete(items, source)
        except Exception:
            return CollectionResult.failed(source)

    def defender_assessments(self) -> CollectionResult[Any]:
        """Collect Defender for Cloud security assessments (recommendations).

        Only configuration metadata is collected: assessment status, severity,
        and non-secret identifiers. Assessment content is never inspected for
        secrets because the SDK model does not expose log or credential data.
        """
        source = "Microsoft.Security/assessments"
        scope = f"/subscriptions/{self._subscription_id}"
        try:
            return CollectionResult.complete(list(self.security.assessments.list(scope)), source)
        except Exception:
            return CollectionResult.failed(source)

    # ------------------------------------------------------------------ #
    # Sentinel auto-discovery (controls 8-10)                            #
    #                                                                    #
    # Design decision (explicitly confirmed): Sentinel workspace scope   #
    # is discovered, never configured. Every Log Analytics workspace in  #
    # the subscription is enumerated, then each workspace's Sentinel     #
    # onboarding state is checked individually. Only workspaces          #
    # confirmed onboarded are queried for data connectors, analytics     #
    # rules, and automation rules. This keeps the policy file free of a  #
    # workspace name so newly onboarded Sentinel workspaces are covered  #
    # automatically on the next scan without a policy change.            #
    # ------------------------------------------------------------------ #

    def log_analytics_workspaces(self) -> CollectionResult[Any]:
        """Collect every Log Analytics workspace in the subscription (subscription-wide)."""
        source = "Microsoft.OperationalInsights/workspaces"
        try:
            return CollectionResult.complete(list(self.log_analytics.workspaces.list()), source)
        except Exception:
            return CollectionResult.failed(source)

    @staticmethod
    def _workspace_resource_group(workspace: Any) -> str:
        """Extract the resource group name from a workspace's ARM resource ID.

        Retained as a thin delegate to the module-level ``workspace_resource_group``
        for backward compatibility with any existing internal call sites.
        """
        return workspace_resource_group(workspace)

    def sentinel_onboarded_workspaces(self) -> CollectionResult[Any]:
        """Discover which Log Analytics workspaces have Microsoft Sentinel onboarded.

        Returns workspace objects (not just names) for every workspace whose
        Sentinel onboarding state was confirmed. Workspaces whose onboarding
        state could not be checked (permission or transport failure) are
        reported as failed scopes via a PARTIAL result rather than silently
        dropped, so callers can distinguish "not onboarded" from "unknown".
        """
        source = "Microsoft.SecurityInsights/onboardingStates"
        workspaces_result = self.log_analytics_workspaces()
        if workspaces_result.status is CollectionStatus.FAILED:
            return CollectionResult.failed(source, workspaces_result.error_code or "COLLECTION_FAILED")

        onboarded: list[Any] = []
        failed_scopes: list[str] = []
        for workspace in workspaces_result.items:
            workspace_name = str(getattr(workspace, "name", "") or "")
            resource_group = self._workspace_resource_group(workspace)
            if not workspace_name or not resource_group:
                failed_scopes.append(str(getattr(workspace, "id", "") or workspace_name or "unknown"))
                continue
            try:
                client = self._sentinel_client(resource_group)
                states = client.sentinel_onboarding_states.list(resource_group, workspace_name)
                values = getattr(states, "value", states) or []
                if len(list(values)) > 0:
                    onboarded.append(workspace)
            except Exception as exc:
                logger.warning(
                    "Sentinel onboarding check failed for workspace %s/%s: %s",
                    resource_group,
                    workspace_name,
                    exc,
                )
                failed_scopes.append(f"{resource_group}/{workspace_name}")

        if failed_scopes and not onboarded:
            return CollectionResult.failed(source, "COLLECTION_FAILED")
        if failed_scopes:
            return CollectionResult.partial(onboarded, source, failed_scopes)
        return CollectionResult.complete(onboarded, source)

    def sentinel_data_connectors(self, workspaces: Sequence[Any]) -> CollectionResult[Mapping[str, tuple[Any, ...]]]:
        """Collect Sentinel data connectors per onboarded workspace."""
        return self._sentinel_collect_per_workspace(
            workspaces, "dataConnectors", lambda c, rg, wn: c.data_connectors.list(rg, wn)
        )

    def sentinel_alert_rules(self, workspaces: Sequence[Any]) -> CollectionResult[Mapping[str, tuple[Any, ...]]]:
        """Collect Sentinel analytics (alert) rules per onboarded workspace."""
        return self._sentinel_collect_per_workspace(
            workspaces, "alertRules", lambda c, rg, wn: c.alert_rules.list(rg, wn)
        )

    def sentinel_automation_rules(self, workspaces: Sequence[Any]) -> CollectionResult[Mapping[str, tuple[Any, ...]]]:
        """Collect Sentinel automation rules per onboarded workspace.

        Automation rules are the Sentinel-native mechanism that routes
        incidents to a playbook (Logic App) or updates incident ownership;
        together with Azure Monitor action groups they are the evidence used
        for control 10's "monitored incident-response destination".
        """
        return self._sentinel_collect_per_workspace(
            workspaces, "automationRules", lambda c, rg, wn: c.automation_rules.list(rg, wn)
        )

    def _sentinel_collect_per_workspace(
        self,
        workspaces: Sequence[Any],
        label: str,
        call: Callable[[Any, str, str], Any],
    ) -> CollectionResult[Mapping[str, tuple[Any, ...]]]:
        source = f"Microsoft.SecurityInsights/{label}"
        collected: dict[str, tuple[Any, ...]] = {}
        failed_scopes: list[str] = []
        for workspace in workspaces:
            workspace_name = str(getattr(workspace, "name", "") or "")
            resource_group = self._workspace_resource_group(workspace)
            key = f"{resource_group}/{workspace_name}"
            try:
                client = self._sentinel_client(resource_group)
                collected[key] = tuple(call(client, resource_group, workspace_name))
            except Exception as exc:
                logger.warning("%s collection failed for workspace %s: %s", label, key, exc)
                failed_scopes.append(key)

        if failed_scopes and not collected:
            return CollectionResult.failed(source)
        if failed_scopes:
            return CollectionResult.partial((collected,), source, failed_scopes)
        return CollectionResult.complete((collected,), source)

    def action_groups(self) -> CollectionResult[Any]:
        """Collect Azure Monitor action groups (subscription-wide).

        Action groups are the concrete Azure notification-destination
        primitive (email/SMS/webhook/ITSM/etc.) available directly through
        the Monitor client that this collector already depends on.
        """
        source = "Microsoft.Insights/actionGroups"
        try:
            return CollectionResult.complete(list(self.monitor.action_groups.list_by_subscription_id()), source)
        except Exception:
            return CollectionResult.failed(source)
