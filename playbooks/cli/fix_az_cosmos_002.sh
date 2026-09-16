#!/bin/bash
# Rule: AZ-COSMOS-002 - Cosmos DB Public Network Access Enabled
set -euo pipefail
RESOURCE_GROUP="${1:-}"; ACCOUNT_NAME="${2:-}"
if [ -z "$RESOURCE_GROUP" ] || [ -z "$ACCOUNT_NAME" ]; then
  echo "Usage: $0 <resource-group> <account-name>"; exit 1
fi
echo "WARNING: Disabling public network access blocks all traffic that does not arrive through a"
echo "private endpoint. Ensure private endpoints are in place before applying."
read -r -p "Type APPLY to confirm the target and operational impact were reviewed: " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }
az account show --output none
az cosmosdb update --resource-group "$RESOURCE_GROUP" --name "$ACCOUNT_NAME" \
  --public-network-access DISABLED
echo "Done. Verify private endpoint connectivity after the change propagates."
