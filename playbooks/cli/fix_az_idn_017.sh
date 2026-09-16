#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-IDN-017 - Global Administrator permanently assigned outside PIM
# Usage: ./fix_az_idn_017.sh <user-id>

set -euo pipefail

USER_ID=${1:-}
if [ -z "$USER_ID" ]; then
  echo "Usage: $0 <user-id>"
  exit 1
fi

echo "Migrating Global Administrator to PIM eligible assignment for user: $USER_ID"
echo ""
echo "Steps:"
echo "1. Open Entra ID > Identity Governance > Privileged Identity Management > Azure AD roles"
echo "2. Select 'Global Administrator' > Assignments > Add eligible assignment > select the user"
echo "3. Set maximum activation duration and require MFA and justification on activation"
echo "4. Remove the permanent active assignment after confirming the eligible assignment works"
echo ""
echo "See: https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-add-role-to-user"
