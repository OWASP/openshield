"""Regression tests for the Azure Resource Graph inventory foundation."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from azure.core.exceptions import HttpResponseError

from scanner.arg_inventory import ArgInventoryClient, InventoryStatus


TENANT_ID = "11111111-1111-1111-1111-111111111111"
SUBSCRIPTION_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
SUBSCRIPTION_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


def _row(
    resource_id: str,
    *,
    subscription_id: str = SUBSCRIPTION_A,
    tenant_id: str = TENANT_ID,
) -> dict:
    return {
        "id": resource_id,
        "name": resource_id.rsplit("/", 1)[-1],
        "type": "Microsoft.Storage/storageAccounts",
        "location": "uksouth",
        "subscriptionId": subscription_id,
        "resourceGroup": "rg-security",
        "tenantId": tenant_id,
        "tags": {"environment": "test"},
        "properties": {"supportsHttpsTrafficOnly": True},
    }


def _response(rows: list[dict], skip_token: str | None = None, result_truncated: bool | str = False):
    return SimpleNamespace(data=rows, skip_token=skip_token, result_truncated=result_truncated)


def _http_error(status_code: int, retry_after: str | None = None) -> HttpResponseError:
    headers = {"Retry-After": retry_after} if retry_after is not None else {}
    response = SimpleNamespace(status_code=status_code, headers=headers, reason="test")
    return HttpResponseError(message="request failed", response=response)


def test_collects_paginated_multi_subscription_snapshot():
    client = MagicMock()
    client.resources.side_effect = [
        _response([_row("/subscriptions/a/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/one")], "next"),
        _response(
            [
                _row(
                    "/subscriptions/b/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/two",
                    subscription_id=SUBSCRIPTION_B,
                )
            ]
        ),
    ]
    clock = iter([10.0, 10.125])

    snapshot = ArgInventoryClient(client=client, monotonic=lambda: next(clock)).collect(
        tenant_id=TENANT_ID,
        subscription_ids=[SUBSCRIPTION_A, SUBSCRIPTION_B],
    )

    assert snapshot.status is InventoryStatus.COMPLETE
    assert snapshot.pages == 2
    assert snapshot.duration_ms == 125
    assert len(snapshot.resources) == 2
    assert {item.subscription_id for item in snapshot.resources} == {SUBSCRIPTION_A, SUBSCRIPTION_B}
    assert all(item.snapshot_id == snapshot.snapshot_id for item in snapshot.resources)
    assert client.resources.call_args_list[0].args[0].options.skip_token is None
    assert client.resources.call_args_list[1].args[0].options.skip_token == "next"


def test_empty_inventory_is_a_complete_snapshot():
    client = MagicMock()
    client.resources.return_value = _response([])

    snapshot = ArgInventoryClient(client=client).collect(
        tenant_id=TENANT_ID,
        subscription_ids=[SUBSCRIPTION_A],
    )

    assert snapshot.status is InventoryStatus.COMPLETE
    assert snapshot.resources == ()
    assert snapshot.errors == ()
    assert snapshot.to_dict()["resource_count"] == 0


def test_retries_throttling_using_retry_after_header():
    client = MagicMock()
    client.resources.side_effect = [_http_error(429, "2"), _response([])]
    delays: list[float] = []

    snapshot = ArgInventoryClient(client=client, sleep=delays.append).collect(
        tenant_id=TENANT_ID,
        subscription_ids=[SUBSCRIPTION_A],
    )

    assert snapshot.status is InventoryStatus.COMPLETE
    assert delays == [2.0]
    assert client.resources.call_count == 2


def test_first_page_failure_is_not_a_clean_snapshot():
    client = MagicMock()
    client.resources.side_effect = _http_error(403)

    snapshot = ArgInventoryClient(client=client).collect(
        tenant_id=TENANT_ID,
        subscription_ids=[SUBSCRIPTION_A],
    )

    assert snapshot.status is InventoryStatus.FAILED
    assert snapshot.pages == 0
    assert snapshot.resources == ()
    assert snapshot.errors == ("ARG query failed with HTTP 403",)


def test_later_page_failure_preserves_resources_as_partial():
    client = MagicMock()
    client.resources.side_effect = [
        _response([_row("/subscriptions/a/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/one")], "next"),
        _http_error(503),
    ]

    snapshot = ArgInventoryClient(client=client, max_retries=0).collect(
        tenant_id=TENANT_ID,
        subscription_ids=[SUBSCRIPTION_A],
    )

    assert snapshot.status is InventoryStatus.PARTIAL
    assert snapshot.pages == 1
    assert len(snapshot.resources) == 1
    assert snapshot.errors == ("ARG query failed with HTTP 503",)


def test_rejects_cross_tenant_and_unauthorised_subscription_rows():
    client = MagicMock()
    client.resources.return_value = _response(
        [
            _row("/subscriptions/a/resourceGroups/rg/providers/type/cross-tenant", tenant_id=SUBSCRIPTION_B),
            _row("/subscriptions/c/resourceGroups/rg/providers/type/cross-sub", subscription_id=SUBSCRIPTION_B),
        ]
    )

    snapshot = ArgInventoryClient(client=client).collect(
        tenant_id=TENANT_ID,
        subscription_ids=[SUBSCRIPTION_A],
    )

    assert snapshot.status is InventoryStatus.PARTIAL
    assert snapshot.resources == ()
    assert any("different tenant" in error for error in snapshot.errors)
    assert any("unauthorised subscription" in error for error in snapshot.errors)


def test_rejects_missing_blank_and_invalid_tenant_ids():
    client = MagicMock()
    missing_tenant = _row("/subscriptions/a/resourceGroups/rg/providers/type/missing-tenant")
    missing_tenant.pop("tenantId")
    blank_tenant = _row("/subscriptions/a/resourceGroups/rg/providers/type/blank-tenant")
    blank_tenant["tenantId"] = ""
    invalid_tenant = _row("/subscriptions/a/resourceGroups/rg/providers/type/invalid-tenant")
    invalid_tenant["tenantId"] = "not-a-uuid"
    client.resources.return_value = _response([missing_tenant, blank_tenant, invalid_tenant])

    snapshot = ArgInventoryClient(client=client).collect(
        tenant_id=TENANT_ID,
        subscription_ids=[SUBSCRIPTION_A],
    )

    assert snapshot.status is InventoryStatus.PARTIAL
    assert snapshot.resources == ()
    assert len(snapshot.errors) == 3
    assert sum("tenantId must be a non-empty string" in error for error in snapshot.errors) == 2
    assert sum("tenantId must be a valid UUID" in error for error in snapshot.errors) == 1


def test_repeated_pagination_token_stops_with_partial_status():
    client = MagicMock()
    client.resources.side_effect = [_response([], "same"), _response([], "same")]

    snapshot = ArgInventoryClient(client=client).collect(
        tenant_id=TENANT_ID,
        subscription_ids=[SUBSCRIPTION_A],
    )

    assert snapshot.status is InventoryStatus.PARTIAL
    assert snapshot.pages == 2
    assert snapshot.errors == ("ARG returned a repeated pagination token",)


def test_truncated_response_without_pagination_token_is_partial():
    client = MagicMock()
    client.resources.return_value = _response(
        [_row("/subscriptions/a/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/one")],
        result_truncated="true",
    )

    snapshot = ArgInventoryClient(client=client).collect(
        tenant_id=TENANT_ID,
        subscription_ids=[SUBSCRIPTION_A],
    )

    assert snapshot.status is InventoryStatus.PARTIAL
    assert len(snapshot.resources) == 1
    assert snapshot.errors == ("ARG reported truncated results without a pagination token",)


def test_scope_requires_valid_non_empty_identifiers():
    collector = ArgInventoryClient(client=MagicMock())

    for tenant_id, subscriptions in [("invalid", [SUBSCRIPTION_A]), (TENANT_ID, []), (TENANT_ID, ["invalid"])]:
        try:
            collector.collect(tenant_id=tenant_id, subscription_ids=subscriptions)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid scope was accepted")


def test_context_manager_closes_sdk_client():
    client = MagicMock()

    with ArgInventoryClient(client=client):
        pass

    client.close.assert_called_once_with()


def test_default_query_contains_bag_merge_and_identity():
    """DEFAULT_QUERY must merge the top-level identity column into properties.

    ARG does not include the identity field in the properties column by default.
    The bag_merge call ensures it is accessible as properties.identity so that
    IdentityToResourceDetector can read it without special-casing the query caller.
    """
    from scanner.arg_inventory import DEFAULT_QUERY

    assert "bag_merge" in DEFAULT_QUERY
    assert "identity" in DEFAULT_QUERY


def test_identity_field_merged_into_properties_is_parsed_by_identity_detector():
    """A row whose identity is merged into properties by bag_merge is detected correctly.

    Simulates the ARG response shape produced by DEFAULT_QUERY: the top-level
    identity column is merged into the properties dict before ArgInventoryClient
    returns it, so IdentityToResourceDetector should find userAssignedIdentities there.
    """
    from scanner.arg_inventory import InventoryResource, InventorySnapshot, InventoryStatus
    from scanner.graph.edge_detector import IdentityToResourceDetector

    vm_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
    identity_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mid1"

    # Simulate what ARG returns after bag_merge(properties, pack('identity', identity)):
    # the resource row has properties.identity set with userAssignedIdentities.
    resource = InventoryResource(
        snapshot_id="snap-kql",
        tenant_id=TENANT_ID,
        subscription_id=SUBSCRIPTION_A,
        resource_id=vm_id,
        resource_type="microsoft.compute/virtualmachines",
        name="vm1",
        location="eastus",
        resource_group="rg",
        tags={},
        properties={"identity": {"userAssignedIdentities": {identity_id: {}}}},
    )
    snapshot = InventorySnapshot(
        snapshot_id="snap-kql",
        tenant_id=TENANT_ID,
        requested_subscriptions=(SUBSCRIPTION_A,),
        status=InventoryStatus.COMPLETE,
        collected_at="2026-09-24T00:00:00+00:00",
        duration_ms=1,
        pages=1,
        resources=(resource,),
        errors=(),
    )

    edges = IdentityToResourceDetector().detect(snapshot)

    assert len(edges) == 1
    assert edges[0].relationship_type == "HAS_IDENTITY"
    assert edges[0].source_resource_id == identity_id
    assert edges[0].target_resource_id == vm_id
