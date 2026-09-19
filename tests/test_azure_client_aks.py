"""Tests for the AzureClient AKS inventory accessor."""

from unittest.mock import MagicMock, patch

from azure.core.exceptions import HttpResponseError

from scanner.azure_client import AzureClient


@patch("scanner.azure_client.ContainerServiceClient")
def test_get_managed_clusters_returns_and_caches_successful_inventory(client_type):
    sdk_client = client_type.return_value
    sdk_client.managed_clusters.list.return_value = ["cluster-a", "cluster-b"]
    client = AzureClient("sub-1", credential=MagicMock())

    assert client.get_managed_clusters() == ["cluster-a", "cluster-b"]
    assert client.get_managed_clusters() == ["cluster-a", "cluster-b"]
    sdk_client.managed_clusters.list.assert_called_once_with()


@patch("scanner.azure_client.ContainerServiceClient")
def test_get_managed_clusters_preserves_empty_successful_inventory(client_type):
    client_type.return_value.managed_clusters.list.return_value = []
    client = AzureClient("sub-1", credential=MagicMock())

    assert client.get_managed_clusters() == []


@patch("scanner.azure_client.ContainerServiceClient")
def test_get_managed_clusters_returns_and_caches_none_on_http_failure(client_type):
    client_type.return_value.managed_clusters.list.side_effect = HttpResponseError(message="forbidden")
    client = AzureClient("sub-1", credential=MagicMock())

    assert client.get_managed_clusters() is None
    assert client.get_managed_clusters() is None
    client_type.return_value.managed_clusters.list.assert_called_once_with()


@patch("scanner.azure_client.ContainerServiceClient")
def test_get_managed_clusters_returns_none_on_unexpected_failure(client_type):
    client_type.return_value.managed_clusters.list.side_effect = RuntimeError("network unavailable")
    client = AzureClient("sub-1", credential=MagicMock())

    assert client.get_managed_clusters() is None


@patch("scanner.aks_security.AksSecurityCollector")
@patch("scanner.azure_client.ContainerServiceClient")
def test_get_aks_security_posture_collects_and_caches(client_type, collector_type):
    clusters = ["cluster-a"]
    client_type.return_value.managed_clusters.list.return_value = clusters
    collector_type.return_value.collect.return_value = ["evidence-a"]
    client = AzureClient("sub-1", credential=MagicMock())

    assert client.get_aks_security_posture() == ["evidence-a"]
    assert client.get_aks_security_posture() == ["evidence-a"]
    collector_type.return_value.collect.assert_called_once_with(clusters)


@patch("scanner.azure_client.ContainerServiceClient")
def test_get_aks_security_posture_preserves_inventory_failure(client_type):
    client_type.return_value.managed_clusters.list.side_effect = RuntimeError("unavailable")
    client = AzureClient("sub-1", credential=MagicMock())

    assert client.get_aks_security_posture() is None
