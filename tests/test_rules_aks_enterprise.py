"""Tests for the issue #255 enterprise AKS and workload rule pack."""

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from scanner.aks_security import AksClusterEvidence
from scanner.rules import (
    az_aks_007,
    az_aks_008,
    az_aks_009,
    az_aks_010,
    az_aks_011,
    az_aks_012,
    az_aks_013,
    az_aks_014,
    az_aks_015,
    az_aks_016,
    az_aks_017,
    az_aks_018,
    az_aks_019,
    az_aks_020,
    az_aks_021,
)
from scanner.rules._aks_enterprise_common import load_policy

RULES = [
    az_aks_007,
    az_aks_008,
    az_aks_009,
    az_aks_010,
    az_aks_011,
    az_aks_012,
    az_aks_013,
    az_aks_014,
    az_aks_015,
    az_aks_016,
    az_aks_017,
    az_aks_018,
    az_aks_019,
    az_aks_020,
    az_aks_021,
]
REQUIRED_METADATA = {
    "cluster",
    "namespace",
    "workload",
    "container",
    "image",
    "subject",
    "role",
    "evidence",
    "remediation",
    "permissions_required",
    "severity",
    "confidence",
    "unknown_reason",
}


def test_every_rule_has_its_own_executable_playbook():
    for rule in RULES:
        path = Path(rule.PLAYBOOK)
        assert path.name == f"fix_{rule.RULE_ID.lower().replace('-', '_')}.sh"
        assert path.is_file()
        assert path.stat().st_mode & 0o111


def cluster(name="aks-1"):
    return SimpleNamespace(
        id=f"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/{name}",
        name=name,
    )


def container(**overrides):
    values = {
        "name": "api",
        "image": "contoso.azurecr.io/app/api@sha256:" + "a" * 64,
        "privileged": False,
        "allow_privilege_escalation": False,
        "run_as_non_root": True,
        "read_only_root_filesystem": True,
        "capabilities_add": (),
        "seccomp_profile": "RuntimeDefault",
    }
    values.update(overrides)
    return values


def workload(**overrides):
    values = {
        "kind": "Deployment",
        "namespace": "payments",
        "name": "api",
        "service_account": "api",
        "automount_service_account_token": False,
        "host_network": False,
        "host_pid": False,
        "host_ipc": False,
        "host_paths": (),
        "native_secret_references": (),
        "csi_secret_provider_classes": ("payments-api",),
        "containers": (container(),),
        "init_containers": (),
    }
    values.update(overrides)
    return values


def evidence(**overrides):
    values = {
        "cluster": cluster(),
        "status": "COMPLETE",
        "source": "test evidence",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "control_plane": {
            "private_cluster_enabled": True,
            "authorized_ip_ranges": (),
            "network_policy": "cilium",
            "defender_for_containers_enabled": True,
            "kms_enabled": True,
            "csi_enabled": True,
            "csi_rotation_enabled": True,
        },
        "namespaces": ("payments",),
        "network_policy_namespaces": ("payments",),
        "workloads": (workload(),),
        "cluster_admin_bindings": ({"binding": "platform", "kind": "Group", "name": "aks-platform-admins"},),
    }
    values.update(overrides)
    return AksClusterEvidence(**values)


@pytest.fixture
def policy_file(tmp_path, monkeypatch):
    path = tmp_path / "aks-policy.json"
    path.write_text(
        """{
  "approved_authorized_ip_ranges": ["203.0.113.0/24"],
  "trusted_registry_prefixes": ["contoso.azurecr.io/"],
  "allowed_cluster_admin_subjects": ["Group:aks-platform-admins"],
  "excluded_namespaces": ["kube-system"],
  "require_image_digests": true
}""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENSHIELD_AKS_SECURITY_POLICY", str(path))
    return path


@pytest.mark.parametrize("rule", RULES)
def test_secure_evidence_has_no_findings(rule, policy_file):
    client = MagicMock()
    client.get_aks_security_posture.return_value = [evidence()]
    assert rule.scan(client, "sub") == []


@pytest.mark.parametrize("rule", RULES)
def test_empty_inventory_is_not_applicable(rule, policy_file):
    client = MagicMock()
    client.get_aks_security_posture.return_value = []
    assert rule.scan(client, "sub") == []


@pytest.mark.parametrize("rule", RULES)
def test_inventory_failure_is_unknown(rule, policy_file):
    client = MagicMock()
    client.get_aks_security_posture.return_value = None
    assert rule.scan(client, "sub") == []


@pytest.mark.parametrize("rule", RULES[6:])
def test_unreachable_cluster_never_creates_workload_findings(rule, policy_file):
    client = MagicMock()
    client.get_aks_security_posture.return_value = [evidence(status="UNKNOWN", unknown_reason="UNREACHABLE")]
    assert rule.scan(client, "sub") == []


@pytest.mark.parametrize(
    ("rule", "changes", "expected_metadata"),
    [
        (az_aks_007, {"private_cluster_enabled": False, "authorized_ip_ranges": ()}, "observed_value"),
        (az_aks_008, {"network_policy": "none"}, "observed_value"),
        (az_aks_010, {"defender_for_containers_enabled": False}, "observed_value"),
        (az_aks_012, {"csi_enabled": True, "csi_rotation_enabled": False}, "observed_value"),
    ],
)
def test_control_plane_violations_emit_complete_evidence(rule, changes, expected_metadata, policy_file):
    item = evidence()
    item.control_plane.update(changes)
    client = MagicMock()
    client.get_aks_security_posture.return_value = [item]
    findings = rule.scan(client, "sub")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == rule.RULE_ID
    assert expected_metadata in findings[0]["metadata"]
    assert findings[0]["metadata"]["unknown_reason"] is None
    assert findings[0]["metadata"]["confidence"] == "HIGH"
    assert REQUIRED_METADATA.issubset(findings[0]["metadata"])


@pytest.mark.parametrize(
    ("rule", "bad_workload", "metadata_key"),
    [
        (az_aks_013, workload(containers=(container(privileged=True),)), "container"),
        (az_aks_014, workload(host_network=True), "workload"),
        (az_aks_015, workload(host_pid=True), "workload"),
        (az_aks_016, workload(host_ipc=True), "workload"),
        (az_aks_017, workload(host_paths=("/var/run",)), "workload"),
        (az_aks_019, workload(containers=(container(image="docker.io/library/nginx@sha256:" + "b" * 64),)), "image"),
        (az_aks_020, workload(containers=(container(image="contoso.azurecr.io/app/api:latest"),)), "image"),
        (az_aks_021, workload(containers=(container(image="contoso.azurecr.io/app/api:1.2.3"),)), "image"),
    ],
)
def test_workload_violations_emit_granular_evidence(rule, bad_workload, metadata_key, policy_file):
    client = MagicMock()
    client.get_aks_security_posture.return_value = [evidence(workloads=(bad_workload,))]
    finding = rule.scan(client, "sub")[0]
    assert finding["resource_type"] == "Kubernetes/workloads"
    assert finding["metadata"]["namespace"] == "payments"
    assert finding["metadata"][metadata_key]
    assert REQUIRED_METADATA.issubset(finding["metadata"])


def test_broad_cluster_admin_and_missing_namespace_policy_are_detected(policy_file):
    client = MagicMock()
    client.get_aks_security_posture.return_value = [
        evidence(
            namespaces=("payments", "orders"),
            network_policy_namespaces=("payments",),
            cluster_admin_bindings=({"binding": "everyone", "kind": "Group", "name": "developers"},),
        )
    ]
    admin = az_aks_018.scan(client, "sub")[0]
    assert admin["metadata"]["subject"] == "Group:developers"
    assert admin["metadata"]["role"] == "cluster-admin"
    namespace = az_aks_009.scan(client, "sub")[0]
    assert namespace["metadata"]["namespace"] == "orders"


def test_service_account_allowlist_is_namespace_scoped(policy_file):
    policy_file.write_text(
        """{
  "approved_authorized_ip_ranges": ["203.0.113.0/24"],
  "trusted_registry_prefixes": ["contoso.azurecr.io/"],
  "allowed_cluster_admin_subjects": ["ServiceAccount:platform:builder"],
  "excluded_namespaces": ["kube-system"],
  "require_image_digests": true
}""",
        encoding="utf-8",
    )
    client = MagicMock()
    client.get_aks_security_posture.return_value = [
        evidence(
            cluster_admin_bindings=(
                {
                    "binding": "platform-builder",
                    "kind": "ServiceAccount",
                    "namespace": "platform",
                    "name": "builder",
                },
                {
                    "binding": "attacker-builder",
                    "kind": "ServiceAccount",
                    "namespace": "attacker",
                    "name": "builder",
                },
            )
        )
    ]

    findings = az_aks_018.scan(client, "sub")

    assert len(findings) == 1
    assert findings[0]["metadata"]["subject"] == "ServiceAccount:attacker:builder"


def test_positive_evidence_survives_partial_collection(policy_file):
    client = MagicMock()
    client.get_aks_security_posture.return_value = [
        evidence(status="PARTIAL", partial_reasons=("orders",), workloads=(workload(host_ipc=True),))
    ]
    assert len(az_aks_016.scan(client, "sub")) == 1


def test_failed_namespace_never_becomes_missing_network_policy_finding(policy_file):
    client = MagicMock()
    client.get_aks_security_posture.return_value = [
        evidence(
            status="PARTIAL",
            partial_reasons=("orders",),
            namespaces=("payments", "orders"),
            network_policy_namespaces=("payments",),
        )
    ]
    assert az_aks_009.scan(client, "sub") == []


def test_authorized_subnet_inside_approved_supernet_is_compliant(policy_file):
    item = evidence()
    item.control_plane.update({"private_cluster_enabled": False, "authorized_ip_ranges": ("203.0.113.15/32",)})
    client = MagicMock()
    client.get_aks_security_posture.return_value = [item]
    assert az_aks_007.scan(client, "sub") == []


def test_privileged_init_container_is_detected(policy_file):
    client = MagicMock()
    client.get_aks_security_posture.return_value = [
        evidence(workloads=(workload(init_containers=(container(name="setup", privileged=True),)),))
    ]
    finding = az_aks_013.scan(client, "sub")[0]
    assert finding["metadata"]["container"] == "setup"


def test_implicit_latest_tag_is_detected(policy_file):
    client = MagicMock()
    client.get_aks_security_posture.return_value = [
        evidence(workloads=(workload(containers=(container(image="contoso.azurecr.io/app/api"),)),))
    ]
    assert len(az_aks_020.scan(client, "sub")) == 1


def test_disabled_csi_provider_makes_rotation_not_applicable(policy_file):
    item = evidence()
    item.control_plane.update({"csi_enabled": False, "csi_rotation_enabled": False})
    client = MagicMock()
    client.get_aks_security_posture.return_value = [item]
    assert az_aks_012.scan(client, "sub") == []


def test_native_secret_reference_without_kms_is_detected(policy_file):
    item = evidence(
        workloads=(
            workload(
                native_secret_references=("database-password",),
                csi_secret_provider_classes=(),
            ),
        )
    )
    item.control_plane.update({"kms_enabled": False, "csi_enabled": False})
    client = MagicMock()
    client.get_aks_security_posture.return_value = [item]

    finding = az_aks_011.scan(client, "sub")[0]

    assert finding["metadata"]["observed_value"]["native_secret_references"] == ["database-password"]


@pytest.mark.parametrize(
    ("rule", "field"),
    [
        (az_aks_007, "private_cluster_enabled"),
        (az_aks_009, None),
        (az_aks_010, "defender_for_containers_enabled"),
    ],
)
def test_incomplete_evidence_never_creates_false_findings(rule, field, policy_file):
    item = evidence(status="UNKNOWN", unknown_reason="INCOMPLETE_DISCOVERY")
    if field:
        item.control_plane[field] = None
    client = MagicMock()
    client.get_aks_security_posture.return_value = [item]
    assert rule.scan(client, "sub") == []


@pytest.mark.parametrize("rule", (az_aks_007, az_aks_018, az_aks_019, az_aks_021))
def test_missing_policy_is_unknown_for_policy_driven_rules(rule, monkeypatch):
    monkeypatch.delenv("OPENSHIELD_AKS_SECURITY_POLICY", raising=False)
    client = MagicMock()
    client.get_aks_security_posture.return_value = [evidence()]
    assert rule.scan(client, "sub") == []


@pytest.mark.parametrize(
    ("rule", "item"),
    [
        (
            az_aks_009,
            evidence(namespaces=("payments", "orders"), network_policy_namespaces=("payments",)),
        ),
        (
            az_aks_011,
            evidence(
                control_plane={"kms_enabled": False},
                workloads=(workload(native_secret_references=("database-password",)),),
            ),
        ),
        (az_aks_013, evidence(workloads=(workload(containers=(container(privileged=True),)),))),
        (az_aks_014, evidence(workloads=(workload(host_network=True),))),
        (az_aks_015, evidence(workloads=(workload(host_pid=True),))),
        (az_aks_016, evidence(workloads=(workload(host_ipc=True),))),
        (az_aks_017, evidence(workloads=(workload(host_paths=("/var/run",)),))),
        (
            az_aks_020,
            evidence(workloads=(workload(containers=(container(image="contoso.azurecr.io/app/api:latest"),)),)),
        ),
    ],
)
def test_policy_independent_workload_rules_run_without_policy(rule, item, monkeypatch):
    monkeypatch.delenv("OPENSHIELD_AKS_SECURITY_POLICY", raising=False)
    client = MagicMock()
    client.get_aks_security_posture.return_value = [item]

    assert len(rule.scan(client, "sub")) == 1


@pytest.mark.parametrize(
    ("rule", "item"),
    [
        (
            az_aks_009,
            evidence(
                namespaces=("payments", "istio-system"),
                network_policy_namespaces=("payments",),
            ),
        ),
        (
            az_aks_011,
            evidence(
                control_plane={"kms_enabled": False},
                workloads=(
                    workload(
                        namespace="istio-system",
                        native_secret_references=("mesh-ca",),
                    ),
                ),
            ),
        ),
        (
            az_aks_013,
            evidence(
                workloads=(
                    workload(
                        namespace="istio-system",
                        containers=(container(privileged=True),),
                    ),
                ),
            ),
        ),
        (az_aks_014, evidence(workloads=(workload(namespace="istio-system", host_network=True),))),
        (az_aks_015, evidence(workloads=(workload(namespace="istio-system", host_pid=True),))),
        (az_aks_016, evidence(workloads=(workload(namespace="istio-system", host_ipc=True),))),
        (
            az_aks_017,
            evidence(workloads=(workload(namespace="istio-system", host_paths=("/var/run",)),)),
        ),
        (
            az_aks_020,
            evidence(
                workloads=(
                    workload(
                        namespace="istio-system",
                        containers=(container(image="contoso.azurecr.io/app/api:latest"),),
                    ),
                ),
            ),
        ),
    ],
)
def test_policy_excludes_non_system_namespace_for_every_affected_rule(rule, item, policy_file):
    policy_file.write_text(
        """{
  "approved_authorized_ip_ranges": ["203.0.113.0/24"],
  "trusted_registry_prefixes": ["contoso.azurecr.io/"],
  "allowed_cluster_admin_subjects": ["Group:aks-platform-admins"],
  "excluded_namespaces": ["istio-system"],
  "require_image_digests": true
}""",
        encoding="utf-8",
    )
    client = MagicMock()
    client.get_aks_security_posture.return_value = [item]

    assert rule.scan(client, "sub") == []


@pytest.mark.parametrize("image", ("nginx", "redis:7", "library/nginx:1.29"))
def test_docker_hub_short_form_images_match_trusted_registry(image, policy_file):
    policy_file.write_text(
        """{
  "approved_authorized_ip_ranges": ["203.0.113.0/24"],
  "trusted_registry_prefixes": ["docker.io/"],
  "allowed_cluster_admin_subjects": ["Group:aks-platform-admins"],
  "excluded_namespaces": ["kube-system"],
  "require_image_digests": true
}""",
        encoding="utf-8",
    )
    client = MagicMock()
    client.get_aks_security_posture.return_value = [
        evidence(workloads=(workload(containers=(container(image=image),)),))
    ]

    assert az_aks_019.scan(client, "sub") == []


def test_trusted_registry_prefix_does_not_cross_repository_boundary(policy_file):
    policy_file.write_text(
        """{
  "approved_authorized_ip_ranges": ["203.0.113.0/24"],
  "trusted_registry_prefixes": ["contoso.azurecr.io/team"],
  "allowed_cluster_admin_subjects": ["Group:aks-platform-admins"],
  "excluded_namespaces": ["kube-system"],
  "require_image_digests": true
}""",
        encoding="utf-8",
    )
    client = MagicMock()
    client.get_aks_security_posture.return_value = [
        evidence(
            workloads=(
                workload(
                    containers=(
                        container(name="trusted", image="contoso.azurecr.io/team/api:1.0"),
                        container(name="lookalike", image="contoso.azurecr.io/team-evil/api:1.0"),
                    )
                ),
            )
        )
    ]

    findings = az_aks_019.scan(client, "sub")

    assert len(findings) == 1
    assert findings[0]["metadata"]["container"] == "lookalike"
    assert findings[0]["metadata"]["image"] == "contoso.azurecr.io/team-evil/api:1.0"


def test_policy_validation_rejects_unknown_fields(policy_file):
    assert load_policy(policy_file).require_image_digests is True
    policy_file.write_text('{"unexpected": true}', encoding="utf-8")
    with pytest.raises(ValueError, match="missing or unsupported"):
        load_policy(policy_file)


def test_policy_validation_rejects_service_account_without_namespace(policy_file):
    policy_file.write_text(
        """{
  "approved_authorized_ip_ranges": ["203.0.113.0/24"],
  "trusted_registry_prefixes": ["contoso.azurecr.io/"],
  "allowed_cluster_admin_subjects": ["ServiceAccount:builder"],
  "excluded_namespaces": ["kube-system"],
  "require_image_digests": true
}""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="include a namespace"):
        load_policy(policy_file)


def test_malformed_cluster_identity_is_unknown(policy_file):
    client = MagicMock()
    client.get_aks_security_posture.return_value = [evidence(cluster=cluster(name=""))]
    assert az_aks_013.scan(client, "sub") == []
