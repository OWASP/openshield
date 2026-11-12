"""Tests for subnet node synthesis in graph_populator.

ARG Resources has no top-level rows for subnets — they are nested under the
parent VNet's properties.subnets. _synthesise_subnet_resources extracts them
so populate_graph can write graph_nodes for subnets and edge upserts succeed.
"""

from scanner.arg_inventory import InventoryResource, InventorySnapshot, InventoryStatus
from scanner.graph.graph_populator import _synthesise_subnet_resources

# Realistic ARG response shapes -------------------------------------------------
# These mirror what Azure Resource Graph returns for a VNet with one subnet,
# a NIC attached to that subnet, and a VM with a user-assigned identity.

_TENANT = "00000000-0000-0000-0000-000000000001"
_SUB = "00000000-0000-0000-0000-000000000002"
_SNAP = "snap-test-1"

_VNET_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000002"
    "/resourceGroups/rg-prod"
    "/providers/Microsoft.Network/virtualNetworks/vnet-prod"
)
_SUBNET_ID = _VNET_ID + "/subnets/default"
_NSG_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000002"
    "/resourceGroups/rg-prod"
    "/providers/Microsoft.Network/networkSecurityGroups/nsg-prod"
)
_NIC_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000002"
    "/resourceGroups/rg-prod"
    "/providers/Microsoft.Network/networkInterfaces/nic-prod"
)
_VM_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000002"
    "/resourceGroups/rg-prod"
    "/providers/Microsoft.Compute/virtualMachines/vm-prod"
)
_IDENTITY_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000002"
    "/resourceGroups/rg-prod"
    "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-prod"
)


def _resource(resource_id, resource_type, properties=None):
    return InventoryResource(
        snapshot_id=_SNAP,
        tenant_id=_TENANT,
        subscription_id=_SUB,
        resource_id=resource_id,
        resource_type=resource_type,
        name=resource_id.split("/")[-1],
        location="uksouth",
        resource_group="rg-prod",
        tags={},
        properties=properties or {},
    )


# ARG returns subnets nested inside the VNet properties.subnets array
_VNET = _resource(
    _VNET_ID,
    "microsoft.network/virtualnetworks",
    {
        "subnets": [
            {
                "id": _SUBNET_ID,
                "name": "default",
                "properties": {
                    "addressPrefix": "10.0.0.0/24",
                    "networkSecurityGroup": {"id": _NSG_ID},
                },
            }
        ],
        "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
    },
)

_NSG = _resource(
    _NSG_ID,
    "microsoft.network/networksecuritygroups",
    {"subnets": [{"id": _SUBNET_ID}]},
)

# ARG returns NIC with ipConfigurations.properties.subnet.id
_NIC = _resource(
    _NIC_ID,
    "microsoft.network/networkinterfaces",
    {
        "ipConfigurations": [
            {
                "properties": {
                    "subnet": {"id": _SUBNET_ID},
                    "privateIPAddress": "10.0.0.4",
                }
            }
        ]
    },
)

_VM = _resource(
    _VM_ID,
    "microsoft.compute/virtualmachines",
    {
        "identity": {
            "type": "UserAssigned",
            "userAssignedIdentities": {_IDENTITY_ID: {}},
        }
    },
)


def _snapshot(*resources):
    return InventorySnapshot(
        snapshot_id=_SNAP,
        tenant_id=_TENANT,
        requested_subscriptions=(_SUB,),
        status=InventoryStatus.COMPLETE,
        collected_at="2026-09-30T00:00:00+00:00",
        duration_ms=42,
        pages=1,
        resources=tuple(resources),
        errors=(),
    )


# Tests -------------------------------------------------------------------------


def test_synthesise_extracts_subnet_from_vnet():
    """Subnet nested in VNet properties.subnets must produce a synthetic node."""
    snapshot = _snapshot(_VNET, _NSG, _NIC, _VM)
    subnets = _synthesise_subnet_resources(snapshot)
    assert len(subnets) == 1
    subnet = subnets[0]
    assert subnet.resource_id == _SUBNET_ID
    assert subnet.resource_type == "microsoft.network/virtualnetworks/subnets"
    assert subnet.tenant_id == _TENANT
    assert subnet.subscription_id == _SUB
    assert subnet.name == "default"
    assert subnet.location == "uksouth"


def test_synthesise_subnet_inherits_vnet_metadata():
    """Synthesised subnet must carry VNet's tenant_id, subscription_id and location."""
    snapshot = _snapshot(_VNET)
    subnets = _synthesise_subnet_resources(snapshot)
    assert subnets[0].snapshot_id == _SNAP
    assert subnets[0].resource_group == "rg-prod"


def test_synthesise_subnet_properties_from_arg():
    """Subnet properties block from ARG (addressPrefix, NSG link) must be preserved."""
    snapshot = _snapshot(_VNET)
    subnets = _synthesise_subnet_resources(snapshot)
    assert "addressPrefix" in subnets[0].properties
    assert subnets[0].properties["addressPrefix"] == "10.0.0.0/24"


def test_synthesise_no_subnets_returns_empty():
    """VNet with empty subnets list must not produce any synthetic nodes."""
    vnet_no_subnets = _resource(_VNET_ID, "microsoft.network/virtualnetworks", {"subnets": []})
    snapshot = _snapshot(vnet_no_subnets)
    assert _synthesise_subnet_resources(snapshot) == []


def test_synthesise_non_vnet_resources_ignored():
    """NSGs, NICs, and VMs must not produce subnet synthetics."""
    snapshot = _snapshot(_NSG, _NIC, _VM)
    assert _synthesise_subnet_resources(snapshot) == []


def test_synthesise_missing_subnet_id_skipped():
    """Subnet entry with no id field must be silently skipped."""
    vnet = _resource(
        _VNET_ID,
        "microsoft.network/virtualnetworks",
        {"subnets": [{"name": "broken", "properties": {}}]},
    )
    snapshot = _snapshot(vnet)
    assert _synthesise_subnet_resources(snapshot) == []


def test_nsg_to_subnet_edge_requires_subnet_in_resource_ids():
    """Confirm the original problem: SubnetToResourceDetector drops NIC->subnet
    when subnet is not in resource_ids. After synthesis it must be present."""
    from scanner.graph.edge_detector import SubnetToResourceDetector

    # Without synthesis: NIC->subnet edge is dropped
    snapshot_no_subnet = _snapshot(_NSG, _NIC, _VM)
    edges_without = SubnetToResourceDetector().detect(snapshot_no_subnet)
    assert not any(e.target_resource_id == _SUBNET_ID for e in edges_without), (
        "subnet should not appear in edges when it has no node"
    )

    # With synthesis: subnet is in resource_ids, edge is emitted
    subnets = _synthesise_subnet_resources(_snapshot(_VNET, _NSG, _NIC, _VM))
    from dataclasses import replace as dc_replace

    augmented = dc_replace(
        snapshot_no_subnet,
        resources=snapshot_no_subnet.resources + tuple(subnets),
    )
    edges_with = SubnetToResourceDetector().detect(augmented)
    assert any(e.target_resource_id == _SUBNET_ID for e in edges_with), (
        "NIC->subnet MEMBER_OF edge must be present after subnet synthesis"
    )
