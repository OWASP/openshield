#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-IDN-016 - Privileged user missing phishing-resistant MFA
# Usage: ./fix_az_idn_016.sh <user-id>

set -euo pipefail

USER_ID=${1:-}
if [ -z "$USER_ID" ]; then
  echo "Usage: $0 <user-id>"
  exit 1
fi

echo "Enabling phishing-resistant MFA for privileged user: $USER_ID"
echo ""
echo "Steps:"
echo "1. Navigate to: Entra ID > Security > Authentication methods > Policies > FIDO2 Security Key"
echo "2. Enable the policy and include the target user or their group."
echo "3. Instruct the user to register a FIDO2 key at https://aka.ms/mysecurityinfo"
echo "4. Create a Conditional Access policy requiring Phishing-resistant MFA strength for admin roles."
echo ""
echo "See: https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key"
