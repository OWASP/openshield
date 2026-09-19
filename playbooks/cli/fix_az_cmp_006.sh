#!/bin/bash
set -euo pipefail
# AZ-CMP-006: Associate an NSG with a VM Scale Set's network interface configuration
# Usage: ./fix_az_cmp_006.sh <resource-group> <vmss-name> <nic-config-index> <nsg-resource-id>
#
# Find <nic-config-index> (0-based) with:
#   az vmss show --resource-group <rg> --name <vmss-name> \
#     --query 'virtualMachineProfile.networkProfile.networkInterfaceConfigurations[].name'
#
# If the NSG does not yet exist, create it first:
#   az network nsg create --resource-group <rg> --name <nsg-name>
RESOURCE_GROUP="${1:-}"
VMSS_NAME="${2:-}"
NIC_CONFIG_INDEX="${3:-}"
NSG_ID="${4:-}"

if [ -z "$RESOURCE_GROUP" ] || [ -z "$VMSS_NAME" ] || [ -z "$NIC_CONFIG_INDEX" ] || [ -z "$NSG_ID" ]; then
  echo "Usage: $0 <resource-group> <vmss-name> <nic-config-index> <nsg-resource-id>"
  exit 1
fi

echo "WARNING: this changes the VMSS model and requires upgrading existing instances to take"
echo "effect on already-running VMs, which can briefly disrupt traffic depending on your"
echo "upgrade policy. Review the scale set's upgrade policy before proceeding."

echo "Associating NSG with network interface configuration index $NIC_CONFIG_INDEX on VMSS '$VMSS_NAME'..."

az vmss update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VMSS_NAME" \
  --set "virtualMachineProfile.networkProfile.networkInterfaceConfigurations[$NIC_CONFIG_INDEX].networkSecurityGroup.id=$NSG_ID"

echo "Model updated for $VMSS_NAME. Existing instances still need to be upgraded to pick up the"
echo "change (Manual/Rolling upgrade policy):"
echo "  az vmss update-instances --resource-group $RESOURCE_GROUP --name $VMSS_NAME --instance-ids '*'"
