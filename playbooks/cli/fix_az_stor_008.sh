#!/bin/bash
# Rule: AZ-STOR-008 - Required Storage Customer-Managed Key Protection Missing
set -euo pipefail
RESOURCE_GROUP="${1:-}"; RESOURCE_NAME="${2:-}"; KEY_URI="${3:-}"
if [ -z "$RESOURCE_GROUP" ] || [ -z "$RESOURCE_NAME" ] || [ -z "$KEY_URI" ]; then
  echo "Usage: $0 <resource-group> <storage-account-name> <key-uri>"; exit 1
fi
echo "Customer-managed-key remediation requires a validated Key Vault key URI and operator review."

# Key Vault URIs have the form:
#   https://<vault>.vault.azure.net/keys/<key-name>[/<key-version>]
# Split into the three separate parts that az storage account update requires.
VAULT_URI="${KEY_URI%%/keys/*}"
KEY_PATH="${KEY_URI#*\/keys\/}"
KEY_NAME="${KEY_PATH%%/*}"
if [[ "$KEY_PATH" == */* ]]; then
  KEY_VERSION="${KEY_PATH#*/}"
else
  KEY_VERSION=""
fi

CMD=(az storage account update
  --name "$RESOURCE_NAME"
  --resource-group "$RESOURCE_GROUP"
  --encryption-key-source Microsoft.Keyvault
  --encryption-key-vault "$VAULT_URI"
  --encryption-key-name "$KEY_NAME")

if [ -n "$KEY_VERSION" ]; then
  CMD+=(--encryption-key-version "$KEY_VERSION")
fi

"${CMD[@]}"
