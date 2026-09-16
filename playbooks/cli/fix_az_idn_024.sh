#!/usr/bin/env bash
# AZ-IDN-024 – Remove broad workload identity exclusions from CA policies
set -euo pipefail
echo "Reviewing Conditional Access policies that exclude all workload identities"
echo "1. Open Entra ID > Security > Conditional Access"
echo "2. Review each enabled policy and remove broad 'All service principals' exclusions"
echo "3. Create dedicated Conditional Access for workload identities policies for privileged service principals"
echo "4. Enable Identity Protection monitoring for service principals"
echo "See: https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity"
