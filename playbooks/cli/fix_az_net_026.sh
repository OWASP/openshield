#!/usr/bin/env bash
set -euo pipefail

: "${RESOURCE_GROUP:?Set RESOURCE_GROUP}"
: "${WAF_POLICY_NAME:?Set WAF_POLICY_NAME}"
echo "Update $WAF_POLICY_NAME in $RESOURCE_GROUP with OWASP 3.2 or DRS 2.1+ and Bot Manager 1.0+."
echo "Managed-rule changes require application-specific exclusion testing and are intentionally review-gated."
