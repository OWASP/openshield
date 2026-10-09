"""Azure Resource Graph inventory collection for Evidence Graph snapshots."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from azure.core.exceptions import HttpResponseError
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions


DEFAULT_QUERY = """
Resources
| extend properties = bag_merge(properties, pack('identity', identity))
| project id, name, type, location, subscriptionId, resourceGroup, tenantId, tags, properties
| order by id asc
""".strip()


class InventoryStatus(str, Enum):
    """Completion state for an ARG inventory snapshot."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


@dataclass(frozen=True)
class InventoryResource:
    """A tenant-scoped Azure resource captured within one snapshot boundary."""

    snapshot_id: str
    tenant_id: str
    subscription_id: str
    resource_id: str
    resource_type: str
    name: str
    location: str
    resource_group: str
    tags: dict[str, Any]
    properties: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible resource record."""
        return asdict(self)


@dataclass(frozen=True)
class InventorySnapshot:
    """Evidence boundary for one ARG collection operation."""

    snapshot_id: str
    tenant_id: str
    requested_subscriptions: tuple[str, ...]
    status: InventoryStatus
    collected_at: str
    duration_ms: int
    pages: int
    resources: tuple[InventoryResource, ...]
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible snapshot without losing status context."""
        payload = asdict(self)
        payload["status"] = self.status.value
        payload["resource_count"] = len(self.resources)
        return payload


class ArgInventoryClient:
    """Collect paginated, tenant-isolated resource snapshots through ARG."""

    def __init__(
        self,
        credential: Any | None = None,
        *,
        client: Any | None = None,
        page_size: int = 1000,
        max_retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if client is None and credential is None:
            raise ValueError("credential is required when no Resource Graph client is supplied")
        if not 1 <= page_size <= 1000:
            raise ValueError("page_size must be between 1 and 1000")
        if max_retries < 0:
            raise ValueError("max_retries cannot be negative")

        self.client = client or ResourceGraphClient(credential)
        self.page_size = page_size
        self.max_retries = max_retries
        self._sleep = sleep
        self._monotonic = monotonic

    def close(self) -> None:
        """Close the underlying SDK transport when the collector owns its lifecycle."""
        close = getattr(self.client, "close", None)
        if callable(close):
            close()

    def __enter__(self) -> ArgInventoryClient:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def collect(
        self,
        *,
        tenant_id: str,
        subscription_ids: Sequence[str],
        query: str = DEFAULT_QUERY,
    ) -> InventorySnapshot:
        """Collect one isolated snapshot across the authorised subscriptions."""
        tenant_id = _normalise_uuid(tenant_id, "tenant_id")
        subscriptions = _normalise_subscriptions(subscription_ids)
        if not query.strip():
            raise ValueError("query must not be empty")

        snapshot_id = str(uuid.uuid4())
        started = self._monotonic()
        collected_at = datetime.now(timezone.utc).isoformat()
        resources: list[InventoryResource] = []
        errors: list[str] = []
        seen_resources: set[tuple[str, str]] = set()
        seen_tokens: set[str] = set()
        skip_token: str | None = None
        pages = 0

        while True:
            request = QueryRequest(
                subscriptions=list(subscriptions),
                query=query,
                options=QueryRequestOptions(
                    top=self.page_size,
                    skip_token=skip_token,
                    result_format="objectArray",
                ),
            )
            try:
                response = self._query_with_retry(request)
            except HttpResponseError as exc:
                errors.append(_safe_http_error(exc))
                break

            pages += 1
            rows = getattr(response, "data", []) or []
            if not isinstance(rows, list):
                errors.append(f"page {pages}: ARG returned an unexpected data shape")
                break

            for index, row in enumerate(rows):
                try:
                    resource = _normalise_resource(
                        row,
                        snapshot_id=snapshot_id,
                        tenant_id=tenant_id,
                        authorised_subscriptions=set(subscriptions),
                    )
                except ValueError as exc:
                    errors.append(f"page {pages} row {index}: {exc}")
                    continue

                key = (resource.subscription_id, resource.resource_id.lower())
                if key in seen_resources:
                    continue
                seen_resources.add(key)
                resources.append(resource)

            next_token = str(getattr(response, "skip_token", "") or "")
            if not next_token:
                if _response_is_truncated(response):
                    errors.append("ARG reported truncated results without a pagination token")
                break
            if next_token in seen_tokens:
                errors.append("ARG returned a repeated pagination token")
                break
            seen_tokens.add(next_token)
            skip_token = next_token

        duration_ms = max(0, round((self._monotonic() - started) * 1000))
        if errors and not pages:
            status = InventoryStatus.FAILED
        elif errors:
            status = InventoryStatus.PARTIAL
        else:
            status = InventoryStatus.COMPLETE

        return InventorySnapshot(
            snapshot_id=snapshot_id,
            tenant_id=tenant_id,
            requested_subscriptions=subscriptions,
            status=status,
            collected_at=collected_at,
            duration_ms=duration_ms,
            pages=pages,
            resources=tuple(resources),
            errors=tuple(errors),
        )

    def _query_with_retry(self, request: QueryRequest) -> Any:
        """Retry throttled or temporarily unavailable requests with bounded backoff."""
        for attempt in range(self.max_retries + 1):
            try:
                return self.client.resources(request)
            except HttpResponseError as exc:
                status_code = getattr(exc, "status_code", None)
                if status_code not in {429, 503} or attempt >= self.max_retries:
                    raise
                self._sleep(_retry_delay(exc, attempt))
        raise RuntimeError("unreachable retry state")


def _normalise_uuid(value: str, field: str) -> str:
    """Validate and canonicalise an Azure tenant or subscription identifier."""
    try:
        return str(uuid.UUID(str(value).strip()))
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{field} must be a valid UUID") from exc


def _normalise_subscriptions(subscription_ids: Sequence[str]) -> tuple[str, ...]:
    """Return a stable, non-empty and duplicate-free subscription scope."""
    if isinstance(subscription_ids, (str, bytes)) or not subscription_ids:
        raise ValueError("subscription_ids must be a non-empty sequence")
    return tuple(dict.fromkeys(_normalise_uuid(item, "subscription_id") for item in subscription_ids))


def _normalise_resource(
    row: Any,
    *,
    snapshot_id: str,
    tenant_id: str,
    authorised_subscriptions: set[str],
) -> InventoryResource:
    """Validate an ARG row and bind it to the requested tenant and snapshot."""
    if not isinstance(row, Mapping):
        raise ValueError("resource must be an object")

    resource_id = _required_string(row, "id")
    resource_type = _required_string(row, "type")
    name = _required_string(row, "name")
    subscription_id = _normalise_uuid(_required_string(row, "subscriptionId"), "subscriptionId")
    if subscription_id not in authorised_subscriptions:
        raise ValueError("resource belongs to an unauthorised subscription")

    returned_tenant = _normalise_uuid(_required_string(row, "tenantId"), "tenantId")
    if returned_tenant != tenant_id:
        raise ValueError("resource belongs to a different tenant")

    tags = row.get("tags") or {}
    properties = row.get("properties") or {}
    if not isinstance(tags, Mapping):
        raise ValueError("tags must be an object")
    if not isinstance(properties, Mapping):
        raise ValueError("properties must be an object")

    return InventoryResource(
        snapshot_id=snapshot_id,
        tenant_id=tenant_id,
        subscription_id=subscription_id,
        resource_id=resource_id,
        resource_type=resource_type,
        name=name,
        location=str(row.get("location") or ""),
        resource_group=str(row.get("resourceGroup") or ""),
        tags=dict(tags),
        properties=dict(properties),
    )


def _required_string(row: Mapping[str, Any], field: str) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _response_is_truncated(response: Any) -> bool:
    """Return whether ARG says the result set is incomplete."""
    value = getattr(response, "result_truncated", False)
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return value is True


def _retry_delay(exc: HttpResponseError, attempt: int) -> float:
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", {}) or {}
    retry_after = headers.get("Retry-After") or headers.get("retry-after")
    try:
        return max(0.0, min(float(retry_after), 30.0))
    except (TypeError, ValueError):
        return min(2**attempt, 30)


def _safe_http_error(exc: HttpResponseError) -> str:
    status_code = getattr(exc, "status_code", None)
    return f"ARG query failed with HTTP {status_code}" if status_code else "ARG query failed"
