#!/bin/bash
# Playbook: fix_az_db_008.sh
# Rule: AZ-DB-008 — Azure SQL Server minimum TLS version below 1.2

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <subscription_id>"
  exit 1
fi

SUBSCRIPTION_ID="$1"

echo "Setting subscription..."
az account set --subscription "$SUBSCRIPTION_ID"

echo "Fetching Azure SQL Servers..."
SERVERS=$(az sql server list --subscription "$SUBSCRIPTION_ID" --query "[].{name:name, rg:resourceGroup}" --output tsv)

if [[ -z "$SERVERS" ]]; then
  echo "No Azure SQL Servers found."
  exit 0
fi

while IFS=$'\t' read -r SERVER_NAME RESOURCE_GROUP; do
  echo "Checking $SERVER_NAME in $RESOURCE_GROUP..."
  TLS_VERSION=$(az sql server show --name "$SERVER_NAME" --resource-group "$RESOURCE_GROUP" --query "minimalTlsVersion" --output tsv 2>/dev/null || echo "")

  if [[ "$TLS_VERSION" != "1.2" && "$TLS_VERSION" != "1.3" ]]; then
    echo "Setting minimum TLS version to 1.2 on $SERVER_NAME..."
    az sql server update --name "$SERVER_NAME" --resource-group "$RESOURCE_GROUP" --minimal-tls-version 1.2 --output none
    echo "Done."
  else
    echo "$SERVER_NAME already enforces TLS $TLS_VERSION, skipping."
  fi
done <<< "$SERVERS"

echo "Done. Verify with:"
echo "  az sql server show --name <name> --resource-group <rg> --query minimalTlsVersion"
