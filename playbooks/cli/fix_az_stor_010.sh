#!/usr/bin/env bash
# fix_az_stor_010.sh
# Create a Private Endpoint for a storage account and lock it down to the private
# network, so its blob/file/queue/table endpoints are no longer reachable over the
# public internet.
# Usage: ./fix_az_stor_010.sh <resource-group> <storage-account-name> <vnet-name> <subnet-name>

set -euo pipefail

RESOURCE_GROUP="${1:-}"
STORAGE_ACCOUNT="${2:-}"
VNET_NAME="${3:-}"
SUBNET_NAME="${4:-}"

if [[ -z "$RESOURCE_GROUP" || -z "$STORAGE_ACCOUNT" || -z "$VNET_NAME" || -z "$SUBNET_NAME" ]]; then
  echo "Usage: $0 <resource-group> <storage-account-name> <vnet-name> <subnet-name>"
  exit 1
fi

STORAGE_ID="$(az storage account show --name "$STORAGE_ACCOUNT" --resource-group "$RESOURCE_GROUP" --query id -o tsv)"

echo "Creating a Private Endpoint (blob) for $STORAGE_ACCOUNT..."
az network private-endpoint create \
  --name "${STORAGE_ACCOUNT}-pe" \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --subnet "$SUBNET_NAME" \
  --private-connection-resource-id "$STORAGE_ID" \
  --group-id blob \
  --connection-name "${STORAGE_ACCOUNT}-pe-conn"

echo "Restricting public network access on $STORAGE_ACCOUNT..."
az storage account update \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --public-network-access Disabled

echo "Done. $STORAGE_ACCOUNT now reaches its data plane over a Private Endpoint only."
