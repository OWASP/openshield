#!/bin/bash
# Rule: AZ-STOR-009 - Required Blob Container Immutability Missing
set -euo pipefail
RESOURCE_GROUP="${1:-}"; ACCOUNT_NAME="${2:-}"; CONTAINER_NAME="${3:-}"; DAYS="${4:-30}"
if [ -z "$RESOURCE_GROUP" ] || [ -z "$ACCOUNT_NAME" ] || [ -z "$CONTAINER_NAME" ]; then
  echo "Usage: $0 <resource-group> <storage-account-name> <container-name> [retention-days]"; exit 1
fi
case "$DAYS" in ''|*[!0-9]*) echo "Retention days must be a positive integer."; exit 1;; esac
if [ "$DAYS" -le 0 ]; then echo "Retention days must be positive."; exit 1; fi
echo "Creating an unlocked immutability policy; lock requires separate operator confirmation."
az storage container immutability-policy create --account-name "$ACCOUNT_NAME" --container-name "$CONTAINER_NAME" --resource-group "$RESOURCE_GROUP" --period "$DAYS"
