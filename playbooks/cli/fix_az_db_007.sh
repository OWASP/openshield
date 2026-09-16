#!/bin/bash
# Rule: AZ-DB-007 - SQL Auditing Retention Below Minimum
set -euo pipefail
RESOURCE_GROUP="${1:-}"; SERVER_NAME="${2:-}"; STORAGE_ACCOUNT="${3:-}"; DAYS="${4:-90}"
if [ -z "$RESOURCE_GROUP" ] || [ -z "$SERVER_NAME" ] || [ -z "$STORAGE_ACCOUNT" ]; then
  echo "Usage: $0 <resource-group> <server-name> <storage-account-name> [retention-days]"; exit 1
fi
case "$DAYS" in ''|*[!0-9]*) echo "Retention days must be a positive integer."; exit 1;; esac
if [ "$DAYS" -lt 90 ]; then echo "Retention must be at least 90 days."; exit 1; fi
echo "WARNING: This enables SQL server-level auditing with ${DAYS}-day retention to $STORAGE_ACCOUNT."
echo "Confirm the storage account is approved for audit data and access is logged."
read -r -p "Type APPLY to confirm the target and operational impact were reviewed: " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }
az account show --output none
az sql server audit-policy update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$SERVER_NAME" \
  --state Enabled \
  --storage-account "$STORAGE_ACCOUNT" \
  --retention-days "$DAYS"
echo "Done. Verify auditing is active and retention shows ${DAYS} days in the Azure portal."
