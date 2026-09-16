#!/usr/bin/env bash
set -euo pipefail

: "${RESOURCE_GROUP:?Set RESOURCE_GROUP}"
: "${FIREWALL_NAME:?Set FIREWALL_NAME}"
az network firewall update --resource-group "$RESOURCE_GROUP" --name "$FIREWALL_NAME" --threat-intel-mode Deny
