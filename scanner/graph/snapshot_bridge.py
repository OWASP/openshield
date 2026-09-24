"""Thin wrapper that collects an ARG InventorySnapshot for use inside ScanEngine."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from scanner.arg_inventory import ArgInventoryClient, InventorySnapshot, InventoryStatus

if TYPE_CHECKING:
    from scanner.azure_client import AzureClient

logger = logging.getLogger(__name__)


def collect_snapshot(client: AzureClient, subscription_id: str) -> InventorySnapshot | None:
    """Collect one ARG snapshot for the given subscription.

    Returns None if the collection fails entirely or the ARG service is
    unavailable. A PARTIAL snapshot (some pages succeeded) is returned as-is
    so callers can still use the resources that were collected.
    """
    tenant_id = getattr(client, "tenant_id", None)
    credential = getattr(client, "credential", None)

    if not tenant_id or not credential:
        logger.warning("snapshot_bridge: AzureClient missing tenant_id or credential — skipping ARG collection")
        return None

    try:
        with ArgInventoryClient(credential=credential) as arg:
            snapshot = arg.collect(
                tenant_id=tenant_id,
                subscription_ids=[subscription_id],
            )
    except Exception as exc:
        logger.warning("snapshot_bridge: ARG collection failed — %s", exc)
        return None

    if snapshot.status == InventoryStatus.FAILED:
        logger.warning(
            "snapshot_bridge: ARG collection returned FAILED status (errors: %s)",
            snapshot.errors,
        )
        return None

    if snapshot.status == InventoryStatus.PARTIAL:
        logger.warning(
            "snapshot_bridge: ARG collection is PARTIAL (%d errors) — continuing with %d resources",
            len(snapshot.errors),
            len(snapshot.resources),
        )

    return snapshot
