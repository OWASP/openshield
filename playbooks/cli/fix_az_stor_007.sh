#!/bin/bash
# Rule: AZ-STOR-007 - Storage Account Allows TLS Below 1.2
set -euo pipefail
RESOURCE_GROUP="${1:-}"
RESOURCE_NAME="${2:-}"
if [ -z "$RESOURCE_GROUP" ] || [ -z "$RESOURCE_NAME" ]; then
  echo "Usage: $0 <resource-group> <storage-account-name>"
  exit 1
fi
az storage account update --name "$RESOURCE_NAME" --resource-group "$RESOURCE_GROUP" --min-tls-version TLS1_2
echo "Minimum TLS version set to TLS1_2 for $RESOURCE_NAME."
