#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-IDN-018 - Privileged role assigned outside PIM
# Usage: ./fix_az_idn_018.sh <user-id> <role-definition-id>

set -euo pipefail

USER_ID=${1:-}
ROLE_ID=${2:-}
if [ -z "$USER_ID" ] || [ -z "$ROLE_ID" ]; then
  echo "Usage: $0 <user-id> <role-definition-id>"
  exit 1
fi

echo "Migrating privileged role $ROLE_ID for user $USER_ID to PIM eligible assignment"
echo ""
echo "Steps:"
echo "1. Open Entra ID > Identity Governance > Privileged Identity Management > Azure AD roles"
echo "2. Select the role > Assignments > Add eligible assignment > select the user"
echo "3. Configure activation settings: require MFA, require justification, set time limit"
echo "4. Remove the permanent active assignment"
echo ""
echo "See: https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-add-role-to-user"
