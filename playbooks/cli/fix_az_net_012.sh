#!/usr/bin/env bash
set -euo pipefail

# Fix AZ-NET-012: Enable a VNet flow log via Network Watcher.
#
# NSG flow logs are legacy: Microsoft blocked new NSG flow log creation on
# 2025-06-30 and retires the feature entirely on 2027-09-30. This script only
# ever creates a VNet flow log - the current, supported mechanism - and never
# creates a new NSG flow log. An existing NSG flow log already covering this
# VNet is left untouched.
#
# Usage: ./fix_az_net_012.sh <network_watcher_resource_group> <location> <vnet_id> <storage_account_id>

NETWORK_WATCHER_RG=${1:?Set NETWORK_WATCHER_RG (the Network Watcher resource group, e.g. NetworkWatcherRG)}
LOCATION=${2:?Set LOCATION (the VNet's region, e.g. eastus)}
VNET_ID=${3:?Set VNET_ID (the target VNet's full resource ID)}
STORAGE_ACCOUNT_ID=${4:?Set STORAGE_ACCOUNT_ID}

FLOW_LOG_NAME="$(basename "$VNET_ID")-vnet-flowlog"

echo "Target VNet: $VNET_ID"
echo "Network Watcher resource group: $NETWORK_WATCHER_RG"
echo "Flow log name: $FLOW_LOG_NAME"
echo

echo "Checking for an existing flow log on this target (idempotency check)..."
EXISTING_STATE=$(az network watcher flow-log show \
    --resource-group "$NETWORK_WATCHER_RG" \
    --name "$FLOW_LOG_NAME" \
    --query "enabled" --output tsv 2>/dev/null || echo "NOT_FOUND")

if [ "$EXISTING_STATE" = "true" ]; then
    echo "SKIP: A VNet flow log named $FLOW_LOG_NAME is already enabled for this target. Nothing to do."
    exit 0
fi

echo "Preview of the change that will be applied:"
echo "  az network watcher flow-log create \\"
echo "    --location \"$LOCATION\" \\"
echo "    --resource-group \"$NETWORK_WATCHER_RG\" \\"
echo "    --name \"$FLOW_LOG_NAME\" \\"
echo "    --vnet \"$VNET_ID\" \\"
echo "    --storage-account \"$STORAGE_ACCOUNT_ID\" \\"
echo "    --enabled true"
echo
read -r -p "Type APPLY to create this VNet flow log: " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }

az network watcher flow-log create \
    --location "$LOCATION" \
    --resource-group "$NETWORK_WATCHER_RG" \
    --name "$FLOW_LOG_NAME" \
    --vnet "$VNET_ID" \
    --storage-account "$STORAGE_ACCOUNT_ID" \
    --enabled true \
    --output none

echo "Validating: re-reading the flow log to confirm it reports enabled..."
VERIFIED_STATE=$(az network watcher flow-log show \
    --resource-group "$NETWORK_WATCHER_RG" \
    --name "$FLOW_LOG_NAME" \
    --query "enabled" --output tsv)

if [ "$VERIFIED_STATE" = "true" ]; then
    echo "SUCCESS: VNet flow log $FLOW_LOG_NAME is enabled and verified for $VNET_ID."
else
    echo "FAILED: flow log was created but does not report enabled=true on re-read."
    echo "Rollback: az network watcher flow-log delete --resource-group \"$NETWORK_WATCHER_RG\" --name \"$FLOW_LOG_NAME\""
    exit 1
fi
