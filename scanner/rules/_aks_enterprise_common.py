"""Shared policy and evaluators for issue #255 AKS enterprise controls."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from scanner.rules._aks_common import finding, resource_identity

logger = logging.getLogger(__name__)
POLICY_ENV_VAR = "OPENSHIELD_AKS_SECURITY_POLICY"
KUBERNETES_PERMISSIONS = [
    "get,list namespaces",
    "get,list workloads and pods",
    "get,list networkpolicies.networking.k8s.io",
    "get,list clusterrolebindings.rbac.authorization.k8s.io",
]
ARM_PERMISSIONS = [
    "Microsoft.ContainerService/managedClusters/read",
    "Microsoft.Security/pricings/read",
]


@dataclass(frozen=True)
class AksSecurityPolicy:
    approved_authorized_ip_ranges: frozenset[str]
    trusted_registry_prefixes: tuple[str, ...]
    allowed_cluster_admin_subjects: frozenset[str]
    excluded_namespaces: frozenset[str]
    require_image_digests: bool


def value(item: Any, name: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(name, default)
    return getattr(item, name, default)


def canonical_cluster_admin_subject(kind: str, name: str, namespace: str = "") -> str:
    normalized_kind = kind.strip().lower()
    normalized_name = name.strip()
    normalized_namespace = namespace.strip()
    if not normalized_name:
        raise ValueError("cluster-admin subject name must not be empty")
    if normalized_kind == "serviceaccount":
        if not normalized_namespace:
            raise ValueError("cluster-admin ServiceAccount subjects must include a namespace")
        return f"ServiceAccount:{normalized_namespace}:{normalized_name}"
    if normalized_kind == "group":
        return f"Group:{normalized_name}"
    if normalized_kind == "user":
        return f"User:{normalized_name}"
    raise ValueError("cluster-admin subjects must be Groups, Users, or ServiceAccounts")


def _policy_subject(value: str) -> str:
    parts = [part.strip() for part in value.split(":")]
    if len(parts) == 3 and parts[0].lower() == "serviceaccount":
        return canonical_cluster_admin_subject(parts[0], parts[2], parts[1]).lower()
    if len(parts) == 2:
        return canonical_cluster_admin_subject(parts[0], parts[1]).lower()
    raise ValueError("cluster-admin subjects must use Group:name, User:name, or ServiceAccount:namespace:name")


def load_policy(path: str | Path) -> AksSecurityPolicy:
    with Path(path).open(encoding="utf-8") as handle:
        raw = json.load(handle)
    required = {
        "approved_authorized_ip_ranges",
        "trusted_registry_prefixes",
        "allowed_cluster_admin_subjects",
        "excluded_namespaces",
        "require_image_digests",
    }
    if not isinstance(raw, dict) or set(raw) != required:
        raise ValueError("AKS security policy has missing or unsupported fields")
    for key in required - {"require_image_digests"}:
        if not isinstance(raw[key], list) or any(not isinstance(item, str) or not item.strip() for item in raw[key]):
            raise ValueError(f"{key} must be a list of non-empty strings")
    if not isinstance(raw["require_image_digests"], bool):
        raise ValueError("require_image_digests must be boolean")
    approved_ranges = set()
    for item in raw["approved_authorized_ip_ranges"]:
        approved_ranges.add(str(ipaddress.ip_network(item.strip(), strict=False)))
    prefixes = tuple(item.strip().lower() for item in raw["trusted_registry_prefixes"])
    if any("/" not in item for item in prefixes):
        raise ValueError("trusted registry prefixes must include a registry and repository separator")
    return AksSecurityPolicy(
        approved_authorized_ip_ranges=frozenset(approved_ranges),
        trusted_registry_prefixes=prefixes,
        allowed_cluster_admin_subjects=frozenset(
            _policy_subject(item) for item in raw["allowed_cluster_admin_subjects"]
        ),
        excluded_namespaces=frozenset(item.strip().lower() for item in raw["excluded_namespaces"]),
        require_image_digests=raw["require_image_digests"],
    )


def policy_from_env(rule_id: str) -> AksSecurityPolicy | None:
    path = os.environ.get(POLICY_ENV_VAR)
    if not path:
        logger.warning("%s: %s is not set; result is UNKNOWN", rule_id, POLICY_ENV_VAR)
        return None
    try:
        return load_policy(path)
    except Exception as exc:
        logger.warning("%s: AKS security policy is invalid: %s; result is UNKNOWN", rule_id, exc)
        return None


def _metadata(
    evidence: Any,
    *,
    namespace: str | None = None,
    workload: str | None = None,
    container: str | None = None,
    image: str | None = None,
    subject: str | None = None,
    role: str | None = None,
    observed: Any = None,
    expected: Any = None,
    permissions: list[str] | None = None,
) -> dict[str, Any]:
    cluster = value(evidence, "cluster")
    _, cluster_name = resource_identity(cluster)
    return {
        "cluster": cluster_name,
        "namespace": namespace,
        "workload": workload,
        "container": container,
        "image": image,
        "subject": subject,
        "role": role,
        "evidence_source": value(evidence, "source", "ARM and Kubernetes API"),
        "evidence_collected_at": value(evidence, "collected_at"),
        "observed_value": observed,
        "expected_value": expected,
        "permissions_required": permissions or ARM_PERMISSIONS + KUBERNETES_PERMISSIONS,
        "confidence": "HIGH",
        "unknown_reason": None,
    }


def _emit(module: Mapping[str, Any], evidence: Any, metadata: Mapping[str, Any]) -> dict[str, Any]:
    cluster = value(evidence, "cluster")
    complete_metadata = dict(metadata)
    complete_metadata.update(
        {
            "evidence": {
                "source": metadata.get("evidence_source"),
                "collected_at": metadata.get("evidence_collected_at"),
                "observed": metadata.get("observed_value"),
                "expected": metadata.get("expected_value"),
            },
            "remediation": module["REMEDIATION"],
            "severity": module["SEVERITY"],
        }
    )
    result = finding(
        cluster,
        rule_id=module["RULE_ID"],
        rule_name=module["RULE_NAME"],
        severity=module["SEVERITY"],
        category=module["CATEGORY"],
        description=module["DESCRIPTION"],
        remediation=module["REMEDIATION"],
        playbook=module["PLAYBOOK"],
        frameworks=module["FRAMEWORKS"],
        metadata=complete_metadata,
    )
    namespace = metadata.get("namespace")
    workload = metadata.get("workload")
    if namespace and workload:
        result["resource_id"] = f"{result['resource_id']}/namespaces/{namespace}/workloads/{workload}"
        result["resource_name"] = f"{namespace}/{workload}"
        result["resource_type"] = "Kubernetes/workloads"
    elif namespace:
        result["resource_id"] = f"{result['resource_id']}/namespaces/{namespace}"
        result["resource_name"] = namespace
        result["resource_type"] = "Kubernetes/namespaces"
    return result


def _workloads(evidence: Any, policy: AksSecurityPolicy | None) -> list[Mapping[str, Any]]:
    result = []
    for workload in value(evidence, "workloads", ()) or ():
        namespace = str(value(workload, "namespace", "default") or "default")
        if policy and namespace.lower() in policy.excluded_namespaces:
            continue
        result.append(workload)
    return result


def _normalize_image_registry(image: str) -> str:
    normalized = image.lower()
    registry = normalized.split("/", 1)[0]
    if "/" not in normalized or not ("." in registry or ":" in registry or registry == "localhost"):
        return f"docker.io/{normalized}"
    return normalized


def _matches_trusted_registry_prefix(image: str, prefix: str) -> bool:
    """Match a registry/repository prefix without crossing a repository boundary."""
    if prefix.endswith("/"):
        return image.startswith(prefix)
    if image == prefix:
        return True
    # Tags, digests, and child repositories are valid continuations; a raw
    # string continuation such as ``team-evil`` must not inherit trust.
    return any(image.startswith(f"{prefix}{separator}") for separator in ("/", ":", "@"))


def scan_control(azure_client: Any, module: Mapping[str, Any], control: str) -> list[dict[str, Any]]:
    rule_id = module["RULE_ID"]
    evidence_items = azure_client.get_aks_security_posture()
    if evidence_items is None:
        logger.warning("%s: AKS inventory unavailable; result is UNKNOWN", rule_id)
        return []
    if not evidence_items:
        logger.info("%s: no AKS clusters exist; result is NOT_APPLICABLE", rule_id)
        return []
    policy_required = control in {
        "api_restrictions",
        "cluster_admin",
        "untrusted_registry",
        "mutable_image",
    }
    # Load an operator-supplied policy for every control so shared safeguards,
    # such as excluded namespaces, apply consistently. Only controls whose
    # evaluation depends on organisation-specific values require the policy to
    # be present and valid.
    policy = policy_from_env(rule_id)
    if policy_required and policy is None:
        return []
    approved_networks = (
        [ipaddress.ip_network(item) for item in policy.approved_authorized_ip_ranges]
        if control == "api_restrictions" and policy
        else []
    )
    findings: list[dict[str, Any]] = []
    for evidence in evidence_items:
        cluster = value(evidence, "cluster")
        resource_id, resource_name = resource_identity(cluster)
        if not resource_id or not resource_name:
            logger.warning("%s: malformed cluster identity; result is UNKNOWN", rule_id)
            continue
        cp = value(evidence, "control_plane", {}) or {}

        if control == "api_restrictions":
            private = value(cp, "private_cluster_enabled")
            ranges = tuple(value(cp, "authorized_ip_ranges", ()) or ())
            if private is True:
                continue
            if private is None:
                logger.warning("%s: API exposure is unknown for %s", rule_id, resource_name)
                continue
            normalized: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
            try:
                normalized = {ipaddress.ip_network(item, strict=False) for item in ranges}
            except ValueError:
                logger.warning("%s: malformed authorized IP evidence for %s", rule_id, resource_name)
                continue
            if normalized and all(
                any(actual.version == allowed.version and actual.subnet_of(allowed) for allowed in approved_networks)
                for actual in normalized
            ):
                continue
            findings.append(
                _emit(
                    module,
                    evidence,
                    _metadata(
                        evidence,
                        observed={"private": False, "authorized_ip_ranges": sorted(str(item) for item in normalized)},
                        expected="private API server or only approved IP ranges",
                        permissions=ARM_PERMISSIONS,
                    ),
                )
            )
            continue

        if control in {"network_policy", "defender", "csi_rotation"}:
            field = {
                "network_policy": "network_policy",
                "defender": "defender_for_containers_enabled",
                "csi_rotation": "csi_rotation_enabled",
            }.get(control)
            if control == "network_policy":
                observed = str(value(cp, field, "") or "")
                if observed.lower() in {"azure", "calico", "cilium"}:
                    continue
                if not observed:
                    logger.warning("%s: network policy evidence is unknown for %s", rule_id, resource_name)
                    continue
                expected = "Azure, Calico, or Cilium network policy"
            elif control == "csi_rotation":
                csi_enabled = value(cp, "csi_enabled")
                if csi_enabled is not True:
                    logger.info(
                        "%s: CSI provider is not enabled for %s; result is NOT_APPLICABLE", rule_id, resource_name
                    )
                    continue
                observed = value(cp, field)
                if observed is True:
                    continue
                if observed is None:
                    logger.warning("%s: CSI rotation evidence is unknown for %s", rule_id, resource_name)
                    continue
                expected = True
            else:
                observed = value(cp, field)
                if observed is True:
                    continue
                if observed is None:
                    logger.warning("%s: Defender evidence is unknown for %s", rule_id, resource_name)
                    continue
                expected = True
            findings.append(
                _emit(
                    module,
                    evidence,
                    _metadata(evidence, observed=observed, expected=expected, permissions=ARM_PERMISSIONS),
                )
            )
            continue

        status = str(value(evidence, "status", "UNKNOWN") or "UNKNOWN").upper()
        if status == "UNKNOWN":
            logger.warning("%s: Kubernetes evidence unavailable for %s; result is UNKNOWN", rule_id, resource_name)
            continue
        workloads = _workloads(evidence, policy)
        if control == "secret_protection":
            if value(cp, "kms_enabled") is True:
                continue
            referenced = [
                workload for workload in workloads if tuple(value(workload, "native_secret_references", ()) or ())
            ]
            if not referenced:
                logger.info(
                    "%s: no in-scope references for %s; result is NOT_APPLICABLE",
                    rule_id,
                    resource_name,
                )
                continue
            for workload in referenced:
                findings.append(
                    _workload_finding(
                        module,
                        evidence,
                        workload,
                        None,
                        {
                            "kms_enabled": False,
                            "kms_key_id": str(value(cp, "kms_key_id", "") or ""),
                            "csi_enabled": value(cp, "csi_enabled"),
                            "native_secret_references": list(value(workload, "native_secret_references", ()) or ()),
                            "csi_secret_provider_classes": list(
                                value(workload, "csi_secret_provider_classes", ()) or ()
                            ),
                        },
                        "KMS-backed native Secrets or CSI-only secret references",
                    )
                )
            continue
        if (
            control
            in {
                "privileged",
                "host_network",
                "host_pid",
                "host_ipc",
                "host_path",
                "untrusted_registry",
                "latest_image",
                "mutable_image",
            }
            and not workloads
        ):
            logger.info("%s: no eligible workloads for %s; result is NOT_APPLICABLE", rule_id, resource_name)
            continue

        if control == "network_policy_namespaces":
            discovered = set(value(evidence, "namespaces", ()) or ())
            protected = set(value(evidence, "network_policy_namespaces", ()) or ())
            failed = set(value(evidence, "partial_reasons", ()) or ())
            excluded = policy.excluded_namespaces if policy else frozenset()
            for namespace in sorted(name for name in discovered - protected - failed if name.lower() not in excluded):
                findings.append(
                    _emit(
                        module,
                        evidence,
                        _metadata(
                            evidence,
                            namespace=namespace,
                            observed="no NetworkPolicy",
                            expected="one or more NetworkPolicies",
                        ),
                    )
                )
        elif control == "privileged":
            for workload in workloads:
                containers = tuple(value(workload, "containers", ()) or ()) + tuple(
                    value(workload, "init_containers", ()) or ()
                )
                for container in containers:
                    if value(container, "privileged") is True:
                        findings.append(_workload_finding(module, evidence, workload, container, True, False))
        elif control in {"host_network", "host_pid", "host_ipc"}:
            for workload in workloads:
                if value(workload, control) is True:
                    findings.append(_workload_finding(module, evidence, workload, None, True, False))
        elif control == "host_path":
            for workload in workloads:
                paths = tuple(value(workload, "host_paths", ()) or ())
                if paths:
                    findings.append(
                        _workload_finding(module, evidence, workload, None, list(paths), "no hostPath volumes")
                    )
        elif control == "cluster_admin":
            for binding in value(evidence, "cluster_admin_bindings", ()) or ():
                try:
                    subject = canonical_cluster_admin_subject(
                        str(value(binding, "kind", "") or ""),
                        str(value(binding, "name", "") or ""),
                        str(value(binding, "namespace", "") or ""),
                    )
                except ValueError:
                    logger.warning("%s: ambiguous cluster-admin subject evidence for %s", rule_id, resource_name)
                    continue
                if subject.lower() in policy.allowed_cluster_admin_subjects:
                    continue
                metadata = _metadata(
                    evidence,
                    subject=subject,
                    role="cluster-admin",
                    observed=value(binding, "binding"),
                    expected=sorted(policy.allowed_cluster_admin_subjects),
                )
                findings.append(_emit(module, evidence, metadata))
        elif control in {"untrusted_registry", "latest_image", "mutable_image"}:
            for workload in workloads:
                containers = tuple(value(workload, "containers", ()) or ()) + tuple(
                    value(workload, "init_containers", ()) or ()
                )
                for container in containers:
                    image = str(value(container, "image", "") or "")
                    if not image:
                        logger.warning("%s: image evidence missing for %s", rule_id, value(workload, "name"))
                        continue
                    normalized = _normalize_image_registry(image)
                    trusted = control != "untrusted_registry" or any(
                        _matches_trusted_registry_prefix(normalized, prefix)
                        for prefix in policy.trusted_registry_prefixes
                    )
                    digest = "@sha256:" in normalized
                    latest = normalized.endswith(":latest") or (":" not in normalized.rsplit("/", 1)[-1] and not digest)
                    violates = {
                        "untrusted_registry": not trusted,
                        "latest_image": latest,
                        "mutable_image": bool(policy and policy.require_image_digests and not digest and not latest),
                    }[control]
                    if not violates:
                        continue
                    observed = {"trusted_registry": trusted, "latest_tag": latest, "digest_pinned": digest}
                    expected = {
                        "untrusted_registry": "approved registry prefix",
                        "latest_image": "explicit non-latest image reference",
                        "mutable_image": "sha256 digest-pinned image",
                    }[control]
                    findings.append(_workload_finding(module, evidence, workload, container, observed, expected))
    return findings


def _workload_finding(
    module: Mapping[str, Any], evidence: Any, workload: Mapping[str, Any], container: Any, observed: Any, expected: Any
) -> dict[str, Any]:
    namespace = str(value(workload, "namespace", "default") or "default")
    name = str(value(workload, "name", "") or "")
    return _emit(
        module,
        evidence,
        _metadata(
            evidence,
            namespace=namespace,
            workload=f"{value(workload, 'kind', 'Workload')}/{name}",
            container=str(value(container, "name", "") or "") or None,
            image=str(value(container, "image", "") or "") or None,
            observed=observed,
            expected=expected,
        ),
    )
