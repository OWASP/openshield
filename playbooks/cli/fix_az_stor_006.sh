#!/bin/bash
# Rule: AZ-STOR-006 - Storage Account Shared-Key Authorization Enabled
set -euo pipefail
RESOURCE_GROUP="${1:-}"
RESOURCE_NAME="${2:-}"
if [ -z "$RESOURCE_GROUP" ] || [ -z "$RESOURCE_NAME" ]; then
  echo "Usage: $0 <resource-group> <storage-account-name>"
  exit 1
fi
echo "Disabling shared-key authorization on $RESOURCE_NAME. Verify all clients use Entra ID first."
az storage account update --name "$RESOURCE_NAME" --resource-group "$RESOURCE_GROUP" --allow-shared-key-access false
echo "Remediation complete for $RESOURCE_NAME."
