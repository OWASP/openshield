#!/usr/bin/env bash
# AZ-IDN-020 – Create emergency access (break-glass) accounts
set -euo pipefail
echo "Creating emergency access accounts"
echo "1. Create two cloud-only Global Administrator accounts:"
echo "   az ad user create --display-name 'Emergency Access 1' --user-principal-name 'emergency1@yourdomain.onmicrosoft.com' --password '<strong-random-password>' --force-change-password-next-sign-in false"
echo "2. Assign Global Administrator role to each account"
echo "3. Exclude both accounts from ALL Conditional Access policies"
echo "4. Store credentials in a physical safe — not a password manager"
echo "5. Configure sign-in alerts for both accounts in Microsoft Sentinel or Azure Monitor"
echo "6. Review and rotate credentials at least every 90 days"
echo "See: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access"
