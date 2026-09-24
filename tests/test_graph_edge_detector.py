"""Tests for graph edge detectors."""

from scanner.arg_inventory import InventorySnapshot, InventoryStatus, InventoryResource
from scanner.graph.edge_detector import (
    GraphEdge,  # noqa: F401  — imported to verify public API surface
    NsgToSubnetDetector,
    SubnetToResourceDetector,  # noqa: F401  — imported to verify public API surface
    PublicIpToResourceDetector,
    IdentityToResourceDetector,
    StoragePrivateEndpointDetector,
    detect_all_edges,
)


def _resource(resource_id, resource_type, properties=None, subscription_id="00000000-0000-0000-0000-000000000002"):
    return InventoryResource(
        snapshot_id="snap-1",
        tenant_id="00000000-0000-0000-0000-000000000001",
        subscription_id=subscription_id,
        resource_id=resource_id,
        resource_type=resource_type,
        name=resource_id.split("/")[-1],
        location="eastus",
        resource_group="rg",
        tags={},
        properties=properties or {},
    )


def _snapshot(*resources):
    return InventorySnapshot(
        snapshot_id="snap-1",
        tenant_id="00000000-0000-0000-0000-000000000001",
        requested_subscriptions=("00000000-0000-0000-0000-000000000002",),
        status=InventoryStatus.COMPLETE,
        collected_at="2026-09-24T00:00:00+00:00",
        duration_ms=10,
        pages=1,
        resources=tuple(resources),
        errors=(),
    )


def test_nsg_to_subnet_detects_protects_edge():
    subnet_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/default"
    nsg_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1"
    nsg = _resource(nsg_id, "microsoft.network/networksecuritygroups", {"subnets": [{"id": subnet_id}]})
    snapshot = _snapshot(nsg)
    edges = NsgToSubnetDetector().detect(snapshot)
    assert len(edges) == 1
    assert edges[0].relationship_type == "PROTECTS"
    assert edges[0].source_resource_id == nsg_id
    assert edges[0].target_resource_id == subnet_id
    assert edges[0].confidence == 1.0


def test_nsg_to_subnet_no_subnets_returns_empty():
    nsg = _resource("/nsg1", "microsoft.network/networksecuritygroups", {"subnets": []})
    snapshot = _snapshot(nsg)
    assert NsgToSubnetDetector().detect(snapshot) == []


def test_public_ip_to_resource_detects_exposes_edge():
    vm_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
    pip_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip1"
    pip = _resource(
        pip_id,
        "microsoft.network/publicipaddresses",
        {"ipConfiguration": {"id": vm_id + "/networkInterfaces/nic1/ipConfigurations/ipconfig1"}},
    )
    snapshot = _snapshot(pip)
    edges = PublicIpToResourceDetector().detect(snapshot)
    assert len(edges) == 1
    assert edges[0].relationship_type == "EXPOSES"
    assert edges[0].source_resource_id == pip_id
    assert edges[0].confidence == 1.0


def test_identity_to_resource_detects_has_identity_edge():
    vm_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
    identity_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id1"
    vm = _resource(
        vm_id, "microsoft.compute/virtualmachines", {"identity": {"userAssignedIdentities": {identity_id: {}}}}
    )
    snapshot = _snapshot(vm)
    edges = IdentityToResourceDetector().detect(snapshot)
    assert len(edges) == 1
    assert edges[0].relationship_type == "HAS_IDENTITY"
    assert edges[0].target_resource_id == vm_id
    assert edges[0].confidence == 0.8


def test_storage_private_endpoint_detects_reachable_via_edge():
    storage_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1"
    pe_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/pe1"
    storage = _resource(
        storage_id,
        "microsoft.storage/storageaccounts",
        {"privateEndpointConnections": [{"properties": {"privateEndpoint": {"id": pe_id}}}]},
    )
    snapshot = _snapshot(storage)
    edges = StoragePrivateEndpointDetector().detect(snapshot)
    assert len(edges) == 1
    assert edges[0].relationship_type == "REACHABLE_VIA"
    assert edges[0].confidence == 1.0


def test_detect_all_edges_runs_all_detectors():
    nsg_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1"
    subnet_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/default"
    nsg = _resource(nsg_id, "microsoft.network/networksecuritygroups", {"subnets": [{"id": subnet_id}]})
    snapshot = _snapshot(nsg)
    edges = detect_all_edges(snapshot)
    assert any(e.relationship_type == "PROTECTS" for e in edges)


def test_empty_snapshot_returns_no_edges():
    snapshot = _snapshot()
    assert detect_all_edges(snapshot) == []
