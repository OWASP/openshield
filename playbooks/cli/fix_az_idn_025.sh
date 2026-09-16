#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-IDN-025 - Privileged role-assignable group has no owner
# Usage: ./fix_az_idn_025.sh <group-id> <owner-user-id>

set -euo pipefail

GROUP_ID=${1:-}
OWNER_ID=${2:-}
if [ -z "$GROUP_ID" ] || [ -z "$OWNER_ID" ]; then
  echo "Usage: $0 <group-id> <owner-user-id>"
  exit 1
fi

az account show --output none
echo "Assigning owner $OWNER_ID to privileged group $GROUP_ID"

OWNER_ODATA="https://graph.microsoft.com/v1.0/users/$OWNER_ID"
az rest --method POST \
  --url "https://graph.microsoft.com/v1.0/groups/$GROUP_ID/owners/\$ref" \
  --body "{\"@odata.id\": \"$OWNER_ODATA\"}"

echo "Owner assigned successfully."
echo "Configure an access review: Entra ID > Identity Governance > Access Reviews > New access review"
echo ""
echo "See: https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview"
