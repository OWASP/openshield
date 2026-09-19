"""Failure-aware Azure and Kubernetes evidence collection for AKS controls."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

logger = logging.getLogger(__name__)

KUBECONFIG_ENV_VAR = "OPENSHIELD_AKS_KUBECONFIG"
KUBECONFIG_CONTEXTS_ENV_VAR = "OPENSHIELD_AKS_KUBECONFIG_CONTEXTS"
SYSTEM_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease", "gatekeeper-system"})


class KubeconfigContextUnresolvedError(ValueError):
    """Raised when an explicit resource-ID mapping names no kubeconfig context."""


@dataclass(frozen=True)
class AksClusterEvidence:
    """One cluster's secret-free control-plane and workload posture."""

    cluster: Any
    status: str
    source: str
    collected_at: str
    unknown_reason: str | None = None
    partial_reasons: tuple[str, ...] = field(default_factory=tuple)
    control_plane: Mapping[str, Any] = field(default_factory=dict)
    namespaces: tuple[str, ...] = field(default_factory=tuple)
    network_policy_namespaces: tuple[str, ...] = field(default_factory=tuple)
    workloads: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    cluster_admin_bindings: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)


def _value(item: Any, name: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(name, default)
    return getattr(item, name, default)


def _nested(item: Any, *names: str, default: Any = None) -> Any:
    current = item
    for name in names:
        current = _value(current, name, None)
        if current is None:
            return default
    return current


def _enum(value: Any) -> str:
    return str(getattr(value, "value", value) or "").strip()


def _normalize_cluster_id(resource_id: str) -> str:
    normalized = resource_id.strip().rstrip("/").lower()
    parts = normalized.split("/")
    if (
        len(parts) != 9
        or parts[0]
        or parts[1] != "subscriptions"
        or not parts[2]
        or parts[3] != "resourcegroups"
        or not parts[4]
        or parts[5] != "providers"
        or parts[6] != "microsoft.containerservice"
        or parts[7] != "managedclusters"
        or not parts[8]
    ):
        raise ValueError("kubeconfig context keys must be complete AKS resource IDs")
    return normalized


def load_kubeconfig_contexts(path: str | Path) -> dict[str, str]:
    with Path(path).open(encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict):
        raise ValueError("AKS kubeconfig context mapping must be a JSON object")
    mapping: dict[str, str] = {}
    assigned_contexts: set[str] = set()
    for resource_id, context in raw.items():
        if not isinstance(resource_id, str) or not isinstance(context, str) or not context.strip():
            raise ValueError("AKS kubeconfig context mapping must contain non-empty string keys and values")
        normalized_id = _normalize_cluster_id(resource_id)
        normalized_context = context.strip()
        if normalized_id in mapping:
            raise ValueError("AKS kubeconfig context mapping contains duplicate resource IDs")
        if normalized_context in assigned_contexts:
            raise ValueError("AKS kubeconfig contexts must map to only one cluster resource ID")
        mapping[normalized_id] = normalized_context
        assigned_contexts.add(normalized_context)
    return mapping


def _container(container: Any) -> dict[str, Any]:
    security = _value(container, "security_context")
    capabilities = _nested(security, "capabilities", "add", default=[]) or []
    secret_references: set[str] = set()
    for environment in _value(container, "env", []) or []:
        secret_name = _nested(environment, "value_from", "secret_key_ref", "name")
        if secret_name:
            secret_references.add(str(secret_name))
    for source in _value(container, "env_from", []) or []:
        secret_name = _nested(source, "secret_ref", "name")
        if secret_name:
            secret_references.add(str(secret_name))
    return {
        "name": str(_value(container, "name", "") or ""),
        "image": str(_value(container, "image", "") or ""),
        "privileged": _value(security, "privileged"),
        "allow_privilege_escalation": _value(security, "allow_privilege_escalation"),
        "run_as_non_root": _value(security, "run_as_non_root"),
        "read_only_root_filesystem": _value(security, "read_only_root_filesystem"),
        "capabilities_add": tuple(str(item) for item in capabilities),
        "seccomp_profile": _enum(_nested(security, "seccomp_profile", "type")),
        "native_secret_references": tuple(sorted(secret_references)),
    }


def _workload(kind: str, item: Any) -> dict[str, Any]:
    metadata = _value(item, "metadata")
    spec = _value(item, "spec")
    pod_spec = spec
    if kind == "CronJob":
        pod_spec = _nested(spec, "job_template", "spec", "template", "spec")
    elif kind != "Pod":
        pod_spec = _nested(spec, "template", "spec")
    volumes = _value(pod_spec, "volumes", []) or []
    host_paths = []
    native_secret_references: set[str] = set()
    csi_secret_provider_classes: set[str] = set()
    for volume in volumes:
        path = _nested(volume, "host_path", "path")
        if path:
            host_paths.append(str(path))
        secret_name = _nested(volume, "secret", "secret_name")
        if secret_name:
            native_secret_references.add(str(secret_name))
        for source in _nested(volume, "projected", "sources", default=[]) or []:
            projected_secret_name = _nested(source, "secret", "name")
            if projected_secret_name:
                native_secret_references.add(str(projected_secret_name))
        csi = _value(volume, "csi")
        if str(_value(csi, "driver", "") or "") == "secrets-store.csi.k8s.io":
            attributes = _value(csi, "volume_attributes", {}) or {}
            provider_class = attributes.get("secretProviderClass") if isinstance(attributes, Mapping) else None
            if provider_class:
                csi_secret_provider_classes.add(str(provider_class))
    containers = tuple(_container(container) for container in (_value(pod_spec, "containers", []) or []))
    init_containers = tuple(_container(container) for container in (_value(pod_spec, "init_containers", []) or []))
    for container in containers + init_containers:
        native_secret_references.update(container["native_secret_references"])
    return {
        "kind": kind,
        "namespace": str(_value(metadata, "namespace", "default") or "default"),
        "name": str(_value(metadata, "name", "") or ""),
        "service_account": str(_value(pod_spec, "service_account_name", "default") or "default"),
        "automount_service_account_token": _value(pod_spec, "automount_service_account_token"),
        "host_network": _value(pod_spec, "host_network"),
        "host_pid": _value(pod_spec, "host_pid"),
        "host_ipc": _value(pod_spec, "host_ipc"),
        "host_paths": tuple(host_paths),
        "native_secret_references": tuple(sorted(native_secret_references)),
        "csi_secret_provider_classes": tuple(sorted(csi_secret_provider_classes)),
        "containers": containers,
        "init_containers": init_containers,
    }


class AksSecurityCollector:
    """Collect AKS ARM, Defender, and Kubernetes API evidence without secrets."""

    def __init__(
        self,
        credential: Any,
        subscription_id: str,
        *,
        kubeconfig_path: str | None = None,
        kubeconfig_contexts_path: str | None = None,
    ) -> None:
        self.credential = credential
        self.subscription_id = subscription_id
        self.kubeconfig_path = kubeconfig_path or os.environ.get(KUBECONFIG_ENV_VAR)
        self.kubeconfig_contexts_path = kubeconfig_contexts_path or os.environ.get(KUBECONFIG_CONTEXTS_ENV_VAR)

    def collect(self, clusters: Iterable[Any]) -> list[AksClusterEvidence]:
        defender_enabled = self._defender_for_containers()
        context_mapping, mapping_error = self._load_context_mapping()
        return [
            self._collect_cluster(cluster, defender_enabled, context_mapping, mapping_error) for cluster in clusters
        ]

    def _load_context_mapping(self) -> tuple[Mapping[str, str], str | None]:
        if not self.kubeconfig_contexts_path:
            return {}, "KUBECONFIG_CONTEXTS_NOT_CONFIGURED"
        if not Path(self.kubeconfig_contexts_path).is_file():
            return {}, "KUBECONFIG_CONTEXTS_NOT_FOUND"
        try:
            return load_kubeconfig_contexts(self.kubeconfig_contexts_path), None
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.warning("AKS kubeconfig context mapping is invalid: %s", type(exc).__name__)
            return {}, "KUBECONFIG_CONTEXTS_INVALID"

    def _defender_for_containers(self) -> bool | None:
        try:
            from azure.mgmt.security import SecurityCenter

            pricing = SecurityCenter(self.credential, self.subscription_id).pricings.get("Containers")
            return _enum(_value(pricing, "pricing_tier")).lower() == "standard"
        except Exception as exc:
            logger.warning("Defender for Containers evidence unavailable: %s", type(exc).__name__)
            return None

    def _control_plane(self, cluster: Any, defender_enabled: bool | None) -> dict[str, Any]:
        properties = _value(cluster, "properties", cluster)
        api_profile = _value(properties, "api_server_access_profile")
        network_profile = _value(properties, "network_profile")
        security_profile = _value(properties, "security_profile")
        kms = _value(security_profile, "azure_key_vault_kms")
        addons = _value(properties, "addon_profiles", {}) or {}
        csi = addons.get("azureKeyvaultSecretsProvider") if isinstance(addons, Mapping) else None
        csi_config = _value(csi, "config", {}) or {}
        power_state = _enum(_nested(properties, "power_state", "code"))
        provisioning_state = _enum(_value(properties, "provisioning_state"))
        network_policy = _enum(_value(network_profile, "network_policy"))
        if network_profile is not None and not network_policy:
            network_policy = "none"
        return {
            "private_cluster_enabled": _value(api_profile, "enable_private_cluster"),
            "authorized_ip_ranges": tuple(_value(api_profile, "authorized_ip_ranges", []) or []),
            "network_policy": network_policy,
            "defender_for_containers_enabled": defender_enabled,
            "kms_enabled": _value(kms, "enabled", False) if kms is not None else False,
            "kms_key_id": str(_value(kms, "key_id", "") or ""),
            "csi_enabled": _value(csi, "enabled", False) if csi is not None else False,
            "csi_rotation_enabled": str(csi_config.get("enableSecretRotation", "")).lower() == "true",
            "power_state": power_state,
            "provisioning_state": provisioning_state,
        }

    def _collect_cluster(
        self,
        cluster: Any,
        defender_enabled: bool | None,
        context_mapping: Mapping[str, str],
        mapping_error: str | None,
    ) -> AksClusterEvidence:
        timestamp = datetime.now(timezone.utc).isoformat()
        control_plane = self._control_plane(cluster, defender_enabled)
        if control_plane["power_state"].lower() == "stopped":
            return AksClusterEvidence(
                cluster, "UNKNOWN", "ARM and Kubernetes API", timestamp, "CLUSTER_STOPPED", control_plane=control_plane
            )
        if control_plane["provisioning_state"].lower() in {"canceled", "deleting", "failed"}:
            return AksClusterEvidence(
                cluster,
                "UNKNOWN",
                "ARM and Kubernetes API",
                timestamp,
                "CLUSTER_STATE_UNSUPPORTED",
                control_plane=control_plane,
            )
        if not self.kubeconfig_path:
            return AksClusterEvidence(
                cluster,
                "UNKNOWN",
                "ARM and Kubernetes API",
                timestamp,
                "KUBECONFIG_NOT_CONFIGURED",
                control_plane=control_plane,
            )
        if not Path(self.kubeconfig_path).is_file():
            return AksClusterEvidence(
                cluster,
                "UNKNOWN",
                "ARM and Kubernetes API",
                timestamp,
                "KUBECONFIG_NOT_FOUND",
                control_plane=control_plane,
            )
        if mapping_error:
            return AksClusterEvidence(
                cluster,
                "UNKNOWN",
                "ARM and Kubernetes API",
                timestamp,
                mapping_error,
                control_plane=control_plane,
            )
        try:
            cluster_id = _normalize_cluster_id(str(_value(cluster, "id", "") or ""))
        except ValueError:
            context = None
        else:
            context = context_mapping.get(cluster_id)
        if not context:
            return AksClusterEvidence(
                cluster,
                "UNKNOWN",
                "ARM and Kubernetes API",
                timestamp,
                "KUBECONFIG_CONTEXT_UNRESOLVED",
                control_plane=control_plane,
            )
        try:
            return self._collect_kubernetes(cluster, context, control_plane, timestamp)
        except KubeconfigContextUnresolvedError:
            return AksClusterEvidence(
                cluster,
                "UNKNOWN",
                "ARM and Kubernetes API",
                timestamp,
                "KUBECONFIG_CONTEXT_UNRESOLVED",
                control_plane=control_plane,
            )
        except Exception as exc:
            logger.warning(
                "Kubernetes evidence unavailable for %s: %s",
                _value(cluster, "name", "unknown"),
                type(exc).__name__,
            )
            return AksClusterEvidence(
                cluster,
                "UNKNOWN",
                "ARM and Kubernetes API",
                timestamp,
                "KUBERNETES_API_UNAVAILABLE",
                control_plane=control_plane,
            )

    def _collect_kubernetes(
        self,
        cluster: Any,
        context: str,
        control_plane: Mapping[str, Any],
        timestamp: str,
    ) -> AksClusterEvidence:
        from kubernetes import client, config

        contexts, _ = config.list_kube_config_contexts(config_file=self.kubeconfig_path)
        available_contexts = {str(item.get("name", "")) for item in contexts or () if isinstance(item, Mapping)}
        if context not in available_contexts:
            raise KubeconfigContextUnresolvedError("mapped kubeconfig context does not exist")
        config.load_kube_config(config_file=self.kubeconfig_path, context=context)
        core = client.CoreV1Api()
        apps = client.AppsV1Api()
        batch = client.BatchV1Api()
        networking = client.NetworkingV1Api()
        rbac = client.RbacAuthorizationV1Api()

        try:
            namespace_items = core.list_namespace().items
        except Exception:
            return AksClusterEvidence(
                cluster,
                "UNKNOWN",
                "ARM and Kubernetes API",
                timestamp,
                "NAMESPACE_DISCOVERY_INCOMPLETE",
                control_plane=control_plane,
            )
        namespaces = tuple(
            str(_nested(item, "metadata", "name", default=""))
            for item in namespace_items
            if _nested(item, "metadata", "name")
        )
        eligible = tuple(name for name in namespaces if name not in SYSTEM_NAMESPACES)
        partial: list[str] = []
        policies: set[str] = set()
        workloads: list[Mapping[str, Any]] = []
        for namespace in eligible:
            try:
                if networking.list_namespaced_network_policy(namespace).items:
                    policies.add(namespace)
                workload_calls = (
                    ("Deployment", apps.list_namespaced_deployment),
                    ("StatefulSet", apps.list_namespaced_stateful_set),
                    ("DaemonSet", apps.list_namespaced_daemon_set),
                    ("Job", batch.list_namespaced_job),
                    ("CronJob", batch.list_namespaced_cron_job),
                    ("Pod", core.list_namespaced_pod),
                )
                for kind, call in workload_calls:
                    for item in call(namespace).items:
                        if kind == "Pod" and (_nested(item, "metadata", "owner_references", default=[]) or []):
                            continue
                        workloads.append(_workload(kind, item))
            except Exception:
                partial.append(namespace)

        bindings = []
        try:
            for binding in rbac.list_cluster_role_binding().items:
                if str(_nested(binding, "role_ref", "name", default="")).lower() != "cluster-admin":
                    continue
                metadata = _value(binding, "metadata")
                for subject in _value(binding, "subjects", []) or []:
                    bindings.append(
                        {
                            "binding": str(_value(metadata, "name", "") or ""),
                            "kind": str(_value(subject, "kind", "") or ""),
                            "name": str(_value(subject, "name", "") or ""),
                            "namespace": str(_value(subject, "namespace", "") or ""),
                        }
                    )
        except Exception:
            partial.append("cluster-rbac")

        status = "PARTIAL" if partial else "COMPLETE"
        return AksClusterEvidence(
            cluster=cluster,
            status=status,
            source="ARM, Microsoft Defender for Cloud, and Kubernetes API",
            collected_at=timestamp,
            partial_reasons=tuple(partial),
            control_plane=control_plane,
            namespaces=eligible,
            network_policy_namespaces=tuple(sorted(policies)),
            workloads=tuple(workloads),
            cluster_admin_bindings=tuple(bindings),
        )
