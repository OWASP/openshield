#!/usr/bin/env bash
# AZ-IDN-023 – Enable Identity Protection risk policies
set -euo pipefail
echo "Enabling Identity Protection risk policies"
echo "1. Open Entra ID > Security > Identity Protection"
echo "User risk policy:"
echo "  - Set User risk to 'High'"
echo "  - Set Access to 'Allow access' + 'Require password change'"
echo "  - Enable the policy"
echo "Sign-in risk policy:"
echo "  - Set Sign-in risk to 'Medium and above'"
echo "  - Set Access to 'Allow access' + 'Require multi-factor authentication'"
echo "  - Enable the policy"
echo "Alternatively configure risk-based Conditional Access policies for more granular control."
echo "See: https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies"
