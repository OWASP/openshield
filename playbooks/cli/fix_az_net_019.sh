#!/usr/bin/env bash
set -euo pipefail

: "${PRIVATE_ENDPOINT_ID:?Set PRIVATE_ENDPOINT_ID}"
echo "Review and approve the intended connection, or recreate a rejected/disconnected endpoint: $PRIVATE_ENDPOINT_ID"
echo "Approval is performed on the target PaaS resource and is intentionally not automated by this playbook."
