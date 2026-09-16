#!/usr/bin/env bash
set -euo pipefail

: "${RESOURCE_ID:?Set RESOURCE_ID to the public PaaS resource}"
echo "Validate a private access path before disabling public access on: $RESOURCE_ID"
echo "Use the resource type's Azure CLI command, or document the exact resource ID in OPENSHIELD_PUBLIC_PAAS_EXCEPTIONS."
