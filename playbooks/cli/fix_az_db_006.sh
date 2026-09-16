#!/bin/bash
# Rule: AZ-DB-006 - SQL Server Vulnerability Assessment Not Configured
set -euo pipefail
RESOURCE_GROUP="${1:-}"; SERVER_NAME="${2:-}"; STORAGE_ACCOUNT="${3:-}"; EMAIL="${4:-}"
if [ -z "$RESOURCE_GROUP" ] || [ -z "$SERVER_NAME" ] || [ -z "$STORAGE_ACCOUNT" ] || [ -z "$EMAIL" ]; then
  echo "Usage: $0 <resource-group> <server-name> <storage-account-name> <notification-email>"; exit 1
fi
echo "WARNING: This enables SQL vulnerability assessment and configures scan result storage."
echo "Confirm the storage account is approved for audit data and the email is a monitored address."
read -r -p "Type APPLY to confirm the target and operational impact were reviewed: " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }
az account show --output none
az sql server va-setting update \
  --resource-group "$RESOURCE_GROUP" \
  --server "$SERVER_NAME" \
  --storage-account "$STORAGE_ACCOUNT" \
  --notification-emails "$EMAIL" \
  --email-subscription-admins true \
  --recurring-scans-interval-in-days 7
echo "Done. Verify the first scheduled scan completes and results are delivered to $EMAIL."
