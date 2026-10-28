#!/usr/bin/env bash
# Fix AZ-CI-002: Add least-privilege permissions block to workflow
# Usage: bash fix_az_ci_002.sh <workflow-file>
set -euo pipefail
WORKFLOW="${1:?Usage: $0 <path-to-workflow.yml>}"

echo "[INFO] Add the following to the top level of $WORKFLOW:"
echo ""
echo "permissions:"
echo "  contents: read"
echo ""
echo "[INFO] Override per-job only where broader access is needed."
echo "[INFO] Never use permissions: write-all in production workflows."
echo "[INFO] See: https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs"
