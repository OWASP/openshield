"""Unit tests for failure-aware AKS and Kubernetes evidence collection."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from scanner.aks_security import AksSecurityCollector, load_kubeconfig_contexts

PAYMENTS_CLUSTER_ID = (
    "/subscriptions/sub/resourceGroups/payments/providers/Microsoft.ContainerService/managedClusters/shared"
)
ORDERS_CLUSTER_ID = (
    "/subscriptions/sub/resourceGroups/orders/providers/Microsoft.ContainerService/managedClusters/shared"
)


def ns(**kwargs):
    return SimpleNamespace(**kwargs)


def cluster(**overrides):
    values = {
        "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks-1",
        "name": "aks-1",
        "properties": ns(
            api_server_access_profile=ns(enable_private_cluster=False, authorized_ip_ranges=["203.0.113.0/24"]),
            network_profile=ns(network_policy="cilium"),
            security_profile=ns(azure_key_vault_kms=ns(enabled=True, key_id="key-id")),
            addon_profiles={"azureKeyvaultSecretsProvider": ns(enabled=True, config={"enableSecretRotation": "true"})},
            power_state=ns(code="Running"),
            provisioning_state="Succeeded",
        ),
    }
    values.update(overrides)
    return ns(**values)


def test_stopped_cluster_is_explicitly_unknown():
    stopped = cluster()
    stopped.properties.power_state.code = "Stopped"
    collector = AksSecurityCollector(MagicMock(), "sub", kubeconfig_path="/unused")

    with patch.object(collector, "_defender_for_containers", return_value=True):
        result = collector.collect([stopped])[0]

    assert result.status == "UNKNOWN"
    assert result.unknown_reason == "CLUSTER_STOPPED"
    assert result.control_plane["network_policy"] == "cilium"


def test_unsupported_cluster_state_is_explicitly_unknown():
    failed = cluster()
    failed.properties.provisioning_state = "Failed"
    collector = AksSecurityCollector(MagicMock(), "sub", kubeconfig_path="/unused")

    with patch.object(collector, "_defender_for_containers", return_value=True):
        result = collector.collect([failed])[0]

    assert result.status == "UNKNOWN"
    assert result.unknown_reason == "CLUSTER_STATE_UNSUPPORTED"


def test_missing_kubeconfig_is_explicitly_unknown():
    collector = AksSecurityCollector(MagicMock(), "sub", kubeconfig_path="/does/not/exist")

    with patch.object(collector, "_defender_for_containers", return_value=False):
        result = collector.collect([cluster()])[0]

    assert result.status == "UNKNOWN"
    assert result.unknown_reason == "KUBECONFIG_NOT_FOUND"
    assert result.control_plane["defender_for_containers_enabled"] is False


@patch("azure.mgmt.security.SecurityCenter")
def test_defender_for_containers_preserves_success_and_failure(security_type):
    collector = AksSecurityCollector(MagicMock(), "sub")
    security_type.return_value.pricings.get.return_value = ns(pricing_tier="Standard")
    assert collector._defender_for_containers() is True

    security_type.return_value.pricings.get.side_effect = PermissionError("forbidden")
    assert collector._defender_for_containers() is None


@patch("scanner.aks_security.Path.is_file", return_value=True)
@patch("kubernetes.config.load_kube_config")
@patch("kubernetes.client.RbacAuthorizationV1Api")
@patch("kubernetes.client.NetworkingV1Api")
@patch("kubernetes.client.BatchV1Api")
@patch("kubernetes.client.AppsV1Api")
@patch("kubernetes.client.CoreV1Api")
def test_kubernetes_collection_normalizes_workloads_network_policy_and_rbac(
    core_type,
    apps_type,
    batch_type,
    networking_type,
    rbac_type,
    load_config,
    _is_file,
):
    core = core_type.return_value
    core.list_namespace.return_value = ns(items=[ns(metadata=ns(name="kube-system")), ns(metadata=ns(name="payments"))])
    pod_spec = ns(
        service_account_name="api",
        automount_service_account_token=False,
        host_network=True,
        host_pid=False,
        host_ipc=False,
        volumes=[
            ns(host_path=ns(path="/var/run")),
            ns(secret=ns(secret_name="database-password")),
            ns(projected=ns(sources=[ns(secret=ns(name="projected-token"))])),
            ns(
                csi=ns(
                    driver="secrets-store.csi.k8s.io",
                    volume_attributes={"secretProviderClass": "payments-api"},
                )
            ),
        ],
        containers=[
            ns(
                name="api",
                image="contoso.azurecr.io/api:latest",
                security_context=ns(privileged=True, capabilities=ns(add=["NET_ADMIN"])),
                env=[ns(value_from=ns(secret_key_ref=ns(name="api-token")))],
                env_from=[],
            )
        ],
        init_containers=[],
    )
    deployment = ns(metadata=ns(namespace="payments", name="api"), spec=ns(template=ns(spec=pod_spec)))
    apps_type.return_value.list_namespaced_deployment.return_value = ns(items=[deployment])
    apps_type.return_value.list_namespaced_stateful_set.return_value = ns(items=[])
    apps_type.return_value.list_namespaced_daemon_set.return_value = ns(items=[])
    batch_type.return_value.list_namespaced_job.return_value = ns(items=[])
    batch_type.return_value.list_namespaced_cron_job.return_value = ns(items=[])
    core.list_namespaced_pod.return_value = ns(items=[])
    networking_type.return_value.list_namespaced_network_policy.return_value = ns(items=[object()])
    rbac_type.return_value.list_cluster_role_binding.return_value = ns(
        items=[
            ns(
                metadata=ns(name="developers-admin"),
                role_ref=ns(name="cluster-admin"),
                subjects=[ns(kind="Group", name="developers", namespace=None)],
            )
        ]
    )
    collector = AksSecurityCollector(MagicMock(), "sub", kubeconfig_path="/tmp/kubeconfig")

    with patch(
        "kubernetes.config.list_kube_config_contexts",
        return_value=([{"name": "rg-payments"}], None),
    ):
        result = collector._collect_kubernetes(
            cluster(),
            "rg-payments",
            collector._control_plane(cluster(), True),
            "timestamp",
        )

    load_config.assert_called_once_with(config_file="/tmp/kubeconfig", context="rg-payments")
    assert result.status == "COMPLETE"
    assert result.namespaces == ("payments",)
    assert result.network_policy_namespaces == ("payments",)
    assert result.workloads[0]["host_network"] is True
    assert result.workloads[0]["host_paths"] == ("/var/run",)
    assert result.workloads[0]["containers"][0]["privileged"] is True
    assert result.workloads[0]["native_secret_references"] == (
        "api-token",
        "database-password",
        "projected-token",
    )
    assert result.workloads[0]["csi_secret_provider_classes"] == ("payments-api",)
    assert result.cluster_admin_bindings[0]["name"] == "developers"


@patch("scanner.aks_security.Path.is_file", return_value=True)
@patch("kubernetes.config.load_kube_config")
@patch("kubernetes.client.RbacAuthorizationV1Api")
@patch("kubernetes.client.NetworkingV1Api")
@patch("kubernetes.client.BatchV1Api")
@patch("kubernetes.client.AppsV1Api")
@patch("kubernetes.client.CoreV1Api")
def test_namespace_discovery_failure_is_explicitly_unknown(
    core_type,
    _apps_type,
    _batch_type,
    _networking_type,
    _rbac_type,
    _load_config,
    _is_file,
):
    core_type.return_value.list_namespace.side_effect = PermissionError("forbidden")
    collector = AksSecurityCollector(MagicMock(), "sub", kubeconfig_path="/tmp/kubeconfig")

    with patch(
        "kubernetes.config.list_kube_config_contexts",
        return_value=([{"name": "rg-payments"}], None),
    ):
        result = collector._collect_kubernetes(
            cluster(),
            "rg-payments",
            collector._control_plane(cluster(), True),
            "timestamp",
        )

    assert result.status == "UNKNOWN"
    assert result.unknown_reason == "NAMESPACE_DISCOVERY_INCOMPLETE"


@patch("scanner.aks_security.Path.is_file", return_value=True)
@patch("kubernetes.config.load_kube_config", side_effect=PermissionError("unauthorized"))
@patch("kubernetes.config.list_kube_config_contexts", return_value=([{"name": "rg-payments"}], None))
@patch(
    "scanner.aks_security.load_kubeconfig_contexts",
    return_value={
        "/subscriptions/sub/resourcegroups/rg/providers/microsoft.containerservice/managedclusters/aks-1": "rg-payments"
    },
)
def test_unauthorized_cluster_is_unknown(_load_contexts, _list_contexts, _load_config, _is_file):
    collector = AksSecurityCollector(
        MagicMock(),
        "sub",
        kubeconfig_path="/tmp/kubeconfig",
        kubeconfig_contexts_path="/tmp/contexts.json",
    )

    with patch.object(collector, "_defender_for_containers", return_value=True):
        result = collector.collect([cluster()])[0]

    assert result.status == "UNKNOWN"
    assert result.unknown_reason == "KUBERNETES_API_UNAVAILABLE"


def test_duplicate_cluster_names_use_distinct_resource_id_contexts(tmp_path):
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text("contexts: []", encoding="utf-8")
    contexts = tmp_path / "contexts.json"
    contexts.write_text(
        json.dumps({PAYMENTS_CLUSTER_ID: "payments-context", ORDERS_CLUSTER_ID: "orders-context"}),
        encoding="utf-8",
    )
    collector = AksSecurityCollector(
        MagicMock(),
        "sub",
        kubeconfig_path=str(kubeconfig),
        kubeconfig_contexts_path=str(contexts),
    )
    clusters = [
        cluster(
            id=PAYMENTS_CLUSTER_ID,
            name="shared",
        ),
        cluster(
            id=ORDERS_CLUSTER_ID,
            name="shared",
        ),
    ]

    with (
        patch.object(collector, "_defender_for_containers", return_value=True),
        patch.object(collector, "_collect_kubernetes", side_effect=["payments", "orders"]) as collect_kubernetes,
    ):
        assert collector.collect(clusters) == ["payments", "orders"]

    assert collect_kubernetes.call_args_list[0].args[1] == "payments-context"
    assert collect_kubernetes.call_args_list[1].args[1] == "orders-context"


def test_unmapped_cluster_context_is_explicitly_unknown(tmp_path):
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text("contexts: []", encoding="utf-8")
    contexts = tmp_path / "contexts.json"
    contexts.write_text("{}", encoding="utf-8")
    collector = AksSecurityCollector(
        MagicMock(),
        "sub",
        kubeconfig_path=str(kubeconfig),
        kubeconfig_contexts_path=str(contexts),
    )

    with patch.object(collector, "_defender_for_containers", return_value=True):
        result = collector.collect([cluster()])[0]

    assert result.status == "UNKNOWN"
    assert result.unknown_reason == "KUBECONFIG_CONTEXT_UNRESOLVED"


@patch("kubernetes.config.list_kube_config_contexts", return_value=([{"name": "another-context"}], None))
def test_missing_mapped_kubeconfig_context_is_explicitly_unknown(_list_contexts, tmp_path):
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text("contexts: []", encoding="utf-8")
    contexts = tmp_path / "contexts.json"
    contexts.write_text(
        json.dumps(
            {
                "/subscriptions/sub/resourceGroups/rg/providers/"
                "Microsoft.ContainerService/managedClusters/aks-1": "expected-context"
            }
        ),
        encoding="utf-8",
    )
    collector = AksSecurityCollector(
        MagicMock(),
        "sub",
        kubeconfig_path=str(kubeconfig),
        kubeconfig_contexts_path=str(contexts),
    )

    with patch.object(collector, "_defender_for_containers", return_value=True):
        result = collector.collect([cluster()])[0]

    assert result.status == "UNKNOWN"
    assert result.unknown_reason == "KUBECONFIG_CONTEXT_UNRESOLVED"


def test_context_mapping_rejects_one_context_for_multiple_clusters(tmp_path):
    contexts = tmp_path / "contexts.json"
    contexts.write_text(
        json.dumps({PAYMENTS_CLUSTER_ID: "shared-context", ORDERS_CLUSTER_ID: "shared-context"}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="only one cluster resource ID"):
        load_kubeconfig_contexts(contexts)
