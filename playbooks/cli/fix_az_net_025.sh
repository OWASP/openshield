#!/usr/bin/env bash
set -euo pipefail

: "${APPLICATION_GATEWAY_ID:?Set APPLICATION_GATEWAY_ID}"
echo "Create a diagnostic setting for $APPLICATION_GATEWAY_ID with access, performance, and firewall logs."
echo "Select an approved Log Analytics workspace, Event Hub, or Storage destination before applying the change."
