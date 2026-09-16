#!/usr/bin/env bash
set -euo pipefail

: "${RESOURCE_ID:?Set RESOURCE_ID to the target PaaS resource ID}"
echo "Disable public network access only after validating the Private Endpoint path: $RESOURCE_ID"
echo "Use the service-specific Azure CLI command documented for the target resource type."
