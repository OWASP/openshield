#!/usr/bin/env bash
# AZ-IDN-021 – Block legacy authentication via Conditional Access
set -euo pipefail
echo "Creating Conditional Access policy to block legacy authentication"
echo "1. Open Entra ID > Security > Conditional Access > New policy"
echo "2. Name: Block Legacy Authentication"
echo "3. Users: Include All users"
echo "4. Cloud apps: Include All cloud apps"
echo "5. Conditions > Client apps: select 'Exchange ActiveSync clients' and 'Other clients'"
echo "6. Grant: Block access"
echo "7. Enable policy (run in Report-only mode first to identify affected users)"
echo "See: https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication"
