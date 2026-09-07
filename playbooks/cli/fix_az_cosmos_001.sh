#!/bin/bash
# Rule: AZ-COSMOS-001 - Cosmos DB Local Authentication Enabled
set -euo pipefail
RESOURCE_GROUP="${1:-}"; ACCOUNT_NAME="${2:-}"
if [ -z "$RESOURCE_GROUP" ] || [ -z "$ACCOUNT_NAME" ]; then
  echo "Usage: $0 <resource-group> <account-name>"; exit 1
fi
echo "WARNING: Disabling local authentication prevents all connection-string and key-based access."
echo "Verify that every client uses Entra-based RBAC before applying."
read -r -p "Type APPLY to confirm the target and operational impact were reviewed: " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }
az account show --output none
az cosmosdb update --resource-group "$RESOURCE_GROUP" --name "$ACCOUNT_NAME" \
  --disable-local-auth true
echo "Done. Confirm that all clients authenticate via Entra after the change propagates."
