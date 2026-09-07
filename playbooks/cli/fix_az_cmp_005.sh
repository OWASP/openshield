#!/bin/bash
# fix_az_cmp_005.sh
# Enables Trusted Launch (Secure Boot + vTPM) on a Generation 2 VM
# Usage: ./fix_az_cmp_005.sh <resource-group> <vm-name>
# Note: only supported on Gen2 VM sizes/images; the update requires a restart to take effect.

set -euo pipefail

RG="${1:-}"
VM="${2:-}"

if [ -z "$RG" ] || [ -z "$VM" ]; then
  echo "Usage: $0 <resource-group> <vm-name>"
  exit 1
fi

echo "Enabling Trusted Launch (Secure Boot + vTPM) on VM $VM..."

az vm update \
  --resource-group "$RG" \
  --name "$VM" \
  --security-type TrustedLaunch \
  --enable-secure-boot true \
  --enable-vtpm true

echo "Done. Trusted Launch enabled on $VM. A restart may be required for it to take effect."
