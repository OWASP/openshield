#!/usr/bin/env bash
# Fix AZ-CI-001: Replace long-lived Azure credentials with workload identity federation
# Usage: bash fix_az_ci_001.sh <AZURE_APP_ID> <TENANT_ID> <SUBSCRIPTION_ID> <REPO>
set -euo pipefail
APP_ID="${1:?Usage: $0 <app-id> <tenant-id> <subscription-id> <repo>}"
TENANT_ID="${2:?}"
SUBSCRIPTION_ID="${3:?}"
REPO="${4:?}"

echo "[1/4] Creating federated identity credential for GitHub Actions..."
az ad app federated-credential create \
  --id "$APP_ID" \
  --parameters "{
    \"name\": \"github-oidc\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"repo:${REPO}:ref:refs/heads/main\",
    \"audiences\": [\"api://AzureADTokenExchange\"]
  }"

echo "[2/4] Update workflow: add id-token: write permission"
echo "      Replace azure/login with:"
echo "      - uses: azure/login@v2"
echo "        with:"
echo "          client-id: \${{ secrets.AZURE_CLIENT_ID }}"
echo "          tenant-id: \${{ secrets.AZURE_TENANT_ID }}"
echo "          subscription-id: \${{ secrets.AZURE_SUBSCRIPTION_ID }}"

echo "[3/4] Remove AZURE_CLIENT_SECRET from repository secrets"
gh secret delete AZURE_CLIENT_SECRET --repo "$REPO" 2>/dev/null || true
gh secret delete ARM_CLIENT_SECRET --repo "$REPO" 2>/dev/null || true

echo "[4/4] Done. Validate with: az login --federated-token"
