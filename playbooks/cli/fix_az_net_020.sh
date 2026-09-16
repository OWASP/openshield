#!/usr/bin/env bash
set -euo pipefail

: "${RESOURCE_GROUP:?Set RESOURCE_GROUP}"
: "${PRIVATE_ENDPOINT_NAME:?Set PRIVATE_ENDPOINT_NAME}"
: "${PRIVATE_DNS_ZONE_ID:?Set PRIVATE_DNS_ZONE_ID}"
az network private-endpoint dns-zone-group create --resource-group "$RESOURCE_GROUP" --endpoint-name "$PRIVATE_ENDPOINT_NAME" --name default --private-dns-zone "$PRIVATE_DNS_ZONE_ID" --zone-name default
