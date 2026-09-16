#!/usr/bin/env bash
# AZ-IDN-022 – Require MFA for Azure management via Conditional Access
set -euo pipefail
echo "Creating Conditional Access policy to protect Azure management"
echo "1. Open Entra ID > Security > Conditional Access > New policy"
echo "2. Name: Require MFA for Azure Management"
echo "3. Users: Include All users"
echo "4. Cloud apps: Select 'Microsoft Azure Management' (797f4846-ba00-4fd7-ba43-dac1f8f63013)"
echo "5. Grant: Require multi-factor authentication"
echo "6. Enable policy"
echo "See: https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-azure-management"
