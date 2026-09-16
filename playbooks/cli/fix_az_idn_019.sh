#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-IDN-019 - Stale privileged account retains active access
# Usage: ./fix_az_idn_019.sh <user-id>

set -euo pipefail

USER_ID=${1:-}
if [ -z "$USER_ID" ]; then
  echo "Usage: $0 <user-id>"
  exit 1
fi

az account show --output none
echo "Reviewing stale privileged account: $USER_ID"
az ad user show --id "$USER_ID" \
  --query "{displayName:displayName,accountEnabled:accountEnabled,userPrincipalName:userPrincipalName}" \
  --output table

read -r -p "Disable this account? Type APPLY to confirm: " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }

az ad user update --id "$USER_ID" --account-enabled false
echo "Account disabled. Remove privileged role assignments via PIM or direct role management."
echo ""
echo "See: https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview"
