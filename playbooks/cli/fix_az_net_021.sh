#!/usr/bin/env bash
set -euo pipefail

: "${RESOURCE_GROUP:?Set RESOURCE_GROUP}"
: "${PRIVATE_DNS_ZONE:?Set PRIVATE_DNS_ZONE}"
echo "Inspect records and VNet links before changing production DNS:"
az network private-dns record-set list --resource-group "$RESOURCE_GROUP" --zone-name "$PRIVATE_DNS_ZONE" --output table
az network private-dns link vnet list --resource-group "$RESOURCE_GROUP" --zone-name "$PRIVATE_DNS_ZONE" --output table
