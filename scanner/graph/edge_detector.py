"""Typed edge detectors that infer relationships between Azure resources in an InventorySnapshot."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.arg_inventory import InventorySnapshot

logger = logging.getLogger(__name__)

_NSG_TYPE = "microsoft.network/networksecuritygroups"
_PUBLIC_IP_TYPE = "microsoft.network/publicipaddresses"
_STORAGE_TYPE = "microsoft.storage/storageaccounts"


@dataclass
class GraphEdge:
    """A directed relationship between two Azure resources."""

    source_resource_id: str
    target_resource_id: str
    relationship_type: str
    evidence_source: str
    confidence: float


class EdgeDetector(ABC):
    """Base class for relationship detectors."""

    @abstractmethod
    def detect(self, snapshot: InventorySnapshot) -> list[GraphEdge]:
        """Return edges inferred from this snapshot."""


class NsgToSubnetDetector(EdgeDetector):
    """NSG -> Subnet: PROTECTS (ARG-confirmed, confidence 1.0)."""

    def detect(self, snapshot: InventorySnapshot) -> list[GraphEdge]:
        edges = []
        for resource in snapshot.resources:
            if resource.resource_type.lower() != _NSG_TYPE:
                continue
            subnets = resource.properties.get("subnets") or []
            for subnet in subnets:
                subnet_id = subnet.get("id") if isinstance(subnet, dict) else None
                if not subnet_id:
                    continue
                edges.append(
                    GraphEdge(
                        source_resource_id=resource.resource_id,
                        target_resource_id=subnet_id,
                        relationship_type="PROTECTS",
                        evidence_source="arg:properties.subnets",
                        confidence=1.0,
                    )
                )
        return edges


class SubnetToResourceDetector(EdgeDetector):
    """Resource -> Subnet: MEMBER_OF (inferred from properties, confidence 0.8)."""

    def detect(self, snapshot: InventorySnapshot) -> list[GraphEdge]:
        edges = []
        resource_ids = {r.resource_id.lower() for r in snapshot.resources}
        for resource in snapshot.resources:
            subnet_id = (resource.properties.get("subnet") or {}).get("id")
            if not subnet_id:
                continue
            if subnet_id.lower() not in resource_ids:
                continue
            edges.append(
                GraphEdge(
                    source_resource_id=resource.resource_id,
                    target_resource_id=subnet_id,
                    relationship_type="MEMBER_OF",
                    evidence_source="arg:properties.subnet.id",
                    confidence=0.8,
                )
            )
        return edges


class PublicIpToResourceDetector(EdgeDetector):
    """PublicIP -> Resource: EXPOSES (ARG-confirmed, confidence 1.0)."""

    def detect(self, snapshot: InventorySnapshot) -> list[GraphEdge]:
        edges = []
        for resource in snapshot.resources:
            if resource.resource_type.lower() != _PUBLIC_IP_TYPE:
                continue
            ip_config = resource.properties.get("ipConfiguration") or {}
            target_id = ip_config.get("id")
            if not target_id:
                continue
            # Strip the NIC sub-path to get the parent VM resource ID (4 provider path segments)
            parts = target_id.split("/providers/")
            if len(parts) >= 2:
                provider_path = parts[-1].split("/")
                if len(provider_path) >= 4:
                    target_id = "/providers/".join(parts[:-1]) + "/providers/" + "/".join(provider_path[:4])
            edges.append(
                GraphEdge(
                    source_resource_id=resource.resource_id,
                    target_resource_id=target_id,
                    relationship_type="EXPOSES",
                    evidence_source="arg:properties.ipConfiguration.id",
                    confidence=1.0,
                )
            )
        return edges


class IdentityToResourceDetector(EdgeDetector):
    """Identity -> Resource: HAS_IDENTITY (inferred from properties, confidence 0.8)."""

    def detect(self, snapshot: InventorySnapshot) -> list[GraphEdge]:
        edges = []
        for resource in snapshot.resources:
            identity = resource.properties.get("identity") or {}
            user_assigned = identity.get("userAssignedIdentities") or {}
            for identity_id in user_assigned:
                if not identity_id:
                    continue
                edges.append(
                    GraphEdge(
                        source_resource_id=identity_id,
                        target_resource_id=resource.resource_id,
                        relationship_type="HAS_IDENTITY",
                        evidence_source="arg:properties.identity.userAssignedIdentities",
                        confidence=0.8,
                    )
                )
        return edges


class StoragePrivateEndpointDetector(EdgeDetector):
    """Storage -> PrivateEndpoint: REACHABLE_VIA (ARG-confirmed, confidence 1.0)."""

    def detect(self, snapshot: InventorySnapshot) -> list[GraphEdge]:
        edges = []
        for resource in snapshot.resources:
            if resource.resource_type.lower() != _STORAGE_TYPE:
                continue
            connections = resource.properties.get("privateEndpointConnections") or []
            for conn in connections:
                pe_id = ((conn.get("properties") or {}).get("privateEndpoint") or {}).get("id")
                if not pe_id:
                    continue
                edges.append(
                    GraphEdge(
                        source_resource_id=resource.resource_id,
                        target_resource_id=pe_id,
                        relationship_type="REACHABLE_VIA",
                        evidence_source="arg:properties.privateEndpointConnections",
                        confidence=1.0,
                    )
                )
        return edges


def detect_all_edges(snapshot: InventorySnapshot) -> list[GraphEdge]:
    """Run all detectors and return the combined edge list.

    Per-detector exceptions are caught and logged; the function never raises.
    """
    detectors: list[EdgeDetector] = [
        NsgToSubnetDetector(),
        SubnetToResourceDetector(),
        PublicIpToResourceDetector(),
        IdentityToResourceDetector(),
        StoragePrivateEndpointDetector(),
    ]
    edges: list[GraphEdge] = []
    for detector in detectors:
        try:
            edges.extend(detector.detect(snapshot))
        except Exception as exc:
            logger.warning("edge_detector: %s failed: %s", type(detector).__name__, exc)
    return edges
