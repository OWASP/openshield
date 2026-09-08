#!/bin/bash
# Rule: AZ-CACHE-001 - Managed Cache Public or Non-TLS Access
set -euo pipefail
RESOURCE_GROUP="${1:-}"; CACHE_NAME="${2:-}"
if [ -z "$RESOURCE_GROUP" ] || [ -z "$CACHE_NAME" ]; then
  echo "Usage: $0 <resource-group> <cache-name>"; exit 1
fi
echo "WARNING: Disabling public access or raising the minimum TLS version may interrupt clients that"
echo "connect from approved networks without private endpoints or that use TLS below 1.2."
echo "Validate private endpoint connectivity and client TLS support before applying."
read -r -p "Type APPLY to confirm the target and operational impact were reviewed: " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }
az account show --output none
az redis update --resource-group "$RESOURCE_GROUP" --name "$CACHE_NAME" \
  --set publicNetworkAccess=Disabled minimumTlsVersion=1.2
echo "Done. Verify client connectivity after the update propagates."
