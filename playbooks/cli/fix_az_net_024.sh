#!/usr/bin/env bash
set -euo pipefail

: "${RESOURCE_GROUP:?Set RESOURCE_GROUP}"
: "${WAF_POLICY_NAME:?Set WAF_POLICY_NAME}"
az network application-gateway waf-policy policy-setting update --resource-group "$RESOURCE_GROUP" --policy-name "$WAF_POLICY_NAME" --mode Prevention
