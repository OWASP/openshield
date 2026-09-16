#!/bin/bash
# Rule: AZ-DB-005 - SQL Server Entra-Only Authentication Not Enforced
set -euo pipefail
RESOURCE_GROUP="${1:-}"; SERVER_NAME="${2:-}"
if [ -z "$RESOURCE_GROUP" ] || [ -z "$SERVER_NAME" ]; then
  echo "Usage: $0 <resource-group> <server-name>"; exit 1
fi
echo "WARNING: Enabling Microsoft Entra-only authentication disables all SQL password logins"
echo "including the server administrator account. Verify every application uses Entra identities."
read -r -p "Type APPLY to confirm the target and operational impact were reviewed: " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }
az account show --output none
az sql server ad-only-auth enable --resource-group "$RESOURCE_GROUP" --server "$SERVER_NAME"
echo "Done. Confirm SQL password logins are disabled and Entra clients connect successfully."
