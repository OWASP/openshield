#!/usr/bin/env bash
# Fix AZ-CI-004: Prevent untrusted PR code from reaching privileged context
# Usage: bash fix_az_ci_004.sh
set -euo pipefail

echo "[INFO] For pull_request_target workflows that check out PR code:"
echo ""
echo "[1/3] Never use actions/checkout with PR head ref in pull_request_target:"
echo "  Remove: ref: \${{ github.event.pull_request.head.sha }}"
echo ""
echo "[2/3] Split privileged and unprivileged steps:"
echo "  - Untrusted build: triggered by pull_request (no secrets)"
echo "  - Privileged deploy: triggered by workflow_run on completed build"
echo ""
echo "[3/3] If checkout of PR code is required, remove all secret access:"
echo "  permissions:"
echo "    contents: read"
echo "  env: {} # no secrets"
echo ""
echo "[INFO] See: https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"
