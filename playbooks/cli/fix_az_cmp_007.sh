#!/usr/bin/env bash
# fix_az_cmp_007.sh
# Enable Microsoft Defender for Cloud Just-In-Time (JIT) VM access so a VM's
# management ports (SSH 22 / RDP 3389) are only opened on approved, time-boxed
# requests instead of standing open to the internet.
#
# The shared 'default' JIT policy is a create-or-update whose PUT replaces the
# whole virtualMachines array, so this script first GETs the current policy and
# merges this VM in (preserving every other VM's JIT config) via
# jit_policy_merge.py before PUTting it back.
#
# Usage: ./fix_az_cmp_007.sh <resource-group> <vm-name> <location>
# Requires: Microsoft Defender for Servers enabled on the subscription.

set -euo pipefail

RESOURCE_GROUP="${1:-}"
VM_NAME="${2:-}"
LOCATION="${3:-}"

if [[ -z "$RESOURCE_GROUP" || -z "$VM_NAME" || -z "$LOCATION" ]]; then
  echo "Usage: $0 <resource-group> <vm-name> <location>"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
VM_ID="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/virtualMachines/${VM_NAME}"
POLICY_URL="https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Security/locations/${LOCATION}/jitNetworkAccessPolicies/default?api-version=2020-01-01"

echo "Reading existing JIT policy (if any) in $LOCATION..."
EXISTING="$(az rest --method GET --url "$POLICY_URL" 2>/dev/null || true)"

echo "Merging $VM_NAME (ports 22, 3389) into the policy without dropping other VMs..."
BODY="$(printf '%s' "$EXISTING" | python3 "${SCRIPT_DIR}/jit_policy_merge.py" "$VM_ID" 22 3389)"

az rest --method PUT --url "$POLICY_URL" --body "$BODY"

echo "Done. JIT policy 'default' now covers $VM_NAME (existing VMs preserved); management ports require an approved, time-boxed request."
