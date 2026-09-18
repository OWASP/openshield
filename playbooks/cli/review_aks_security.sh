#!/bin/bash
# Shared safety gate for issue #255 AKS and Kubernetes remediations.
set -euo pipefail

RULE_ID=${1:-}
TARGET=${2:-}
VALUE=${3:-}
if [ -z "$RULE_ID" ] || [ -z "$TARGET" ]; then
  echo "Usage: $0 <rule-id> <cluster-resource-id-or-kube-context> [approved-value]"
  exit 1
fi

echo "Rule: $RULE_ID"
echo "Target: $TARGET"
echo "WARNING: AKS control-plane, RBAC, network policy, and workload changes can interrupt production."
echo "Validate availability, break-glass access, admission policy, and rollback before continuing."
read -r -p "Type APPLY to confirm that the target and impact were reviewed: " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }

case "$RULE_ID" in
  AZ-AKS-007)
    [ -n "$VALUE" ] || { echo "Provide approved comma-separated IP ranges as the third argument."; exit 1; }
    az account show --output none
    az aks update --ids "$TARGET" --api-server-authorized-ip-ranges "$VALUE"
    ;;
  AZ-AKS-010)
    az account show --output none
    az security pricing create --name Containers --tier Standard
    ;;
  AZ-AKS-011)
    az account show --output none
    echo "Enabling the Key Vault Secrets Store CSI add-on is a prerequisite only."
    echo "It does not migrate existing Kubernetes Secret references or resolve AZ-AKS-011 by itself."
    az aks enable-addons --ids "$TARGET" --addons azure-keyvault-secrets-provider
    echo "Next steps required for each affected workload:"
    echo "  1. Configure AKS Workload Identity and grant its identity least-privilege Key Vault access."
    echo "  2. Create and test a SecretProviderClass that reads the required Key Vault objects."
    echo "  3. Add the secrets-store.csi.k8s.io volume and mount it in the workload."
    echo "  4. Remove native Secret volume, projected Secret, env, and envFrom references from the workload."
    echo "  5. Restart and test the workload, then verify that no native Secret references remain."
    echo "Alternative: enable and validate AKS Key Vault KMS if native Kubernetes Secrets must remain."
    echo "Re-run OpenShield after completing and validating one of these remediation paths."
    ;;
  AZ-AKS-012)
    az account show --output none
    az aks addon update --ids "$TARGET" --addon azure-keyvault-secrets-provider --enable-secret-rotation
    ;;
  *)
    kubectl --context "$TARGET" auth can-i get pods --all-namespaces
    echo "Review completed. Apply the rule-specific remediation from the finding after testing the manifest or RBAC change."
    echo "No Kubernetes object was changed automatically."
    ;;
esac
