#!/usr/bin/env bash
# Fix AZ-CI-003: Pin third-party actions to immutable commit SHAs
# Usage: bash fix_az_ci_003.sh <workflow-file>
set -euo pipefail
WORKFLOW="${1:?Usage: $0 <path-to-workflow.yml>}"

echo "[INFO] For each unpinned action in $WORKFLOW, replace the tag with a full SHA:"
echo "  Before: uses: actions/checkout@v4"
echo "  After:  uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2"
echo ""
echo "[INFO] Use pin-github-action to automate:"
echo "  pip install pin-github-action"
echo "  pin-github-action $WORKFLOW"
echo ""
echo "[INFO] Enable Dependabot to keep pinned SHAs updated:"
echo "  Add to .github/dependabot.yml:"
echo "  - package-ecosystem: github-actions"
echo "    directory: /"
echo "    schedule:"
echo "      interval: weekly"
