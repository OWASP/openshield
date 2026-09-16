#!/usr/bin/env bash
set -euo pipefail

: "${RESOURCE_GROUP:?Set RESOURCE_GROUP}"
: "${WAF_POLICY_NAME:?Set WAF_POLICY_NAME}"
echo "Add an enabled RateLimitRule to WAF policy $WAF_POLICY_NAME in $RESOURCE_GROUP."
echo "Choose threshold, duration, grouping, and match conditions from approved application capacity data."
