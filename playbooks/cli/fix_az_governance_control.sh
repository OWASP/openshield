#!/bin/bash
set -euo pipefail

RULE_ID="${1:-}"
MODE="${2:-}"
shift 2 || true

if [ "$MODE" != "--apply" ]; then
  echo "Usage: fix_az_gov_NNN.sh --apply <rule-specific arguments>"
  echo "This playbook changes Azure governance state. Review the finding evidence and approved policy first."
  exit 1
fi

az account show --output none

case "$RULE_ID" in
  AZ-GOV-001)
    [ "$#" -eq 2 ] || { echo "Arguments: <subscription-id> <management-group-id>"; exit 1; }
    az account management-group subscription add --subscription "$1" --name "$2"
    ;;
  AZ-GOV-002)
    [ "$#" -eq 3 ] || { echo "Arguments: <assignment-name> <initiative-definition-id> <scope>"; exit 1; }
    az policy assignment create --name "$1" --policy-set-definition "$2" --scope "$3"
    ;;
  AZ-GOV-003)
    [ "$#" -eq 3 ] || { echo "Arguments: <assignment-name> <scope> <approved-effect>"; exit 1; }
    az policy assignment update --name "$1" --scope "$2" --params "{\"effect\":{\"value\":\"$3\"}}"
    ;;
  AZ-GOV-004)
    echo "Update the exemption owner, justification, and expiration through the approved governance workflow."
    echo "Automatic exemption metadata changes are intentionally disabled because metadata schemas are organisation-specific."
    exit 2
    ;;
  AZ-GOV-005)
    [ "$#" -eq 2 ] || { echo "Arguments: <resource-id> <lock-name>"; exit 1; }
    az lock create --name "$2" --lock-type CanNotDelete --resource "$1"
    ;;
  AZ-GOV-006|AZ-GOV-007)
    [ "$#" -eq 1 ] || { echo "Arguments: <role-assignment-resource-id>"; exit 1; }
    az role assignment delete --ids "$1"
    ;;
  AZ-GOV-008)
    [ "$#" -eq 1 ] || { echo "Arguments: <provider-namespace>"; exit 1; }
    az provider unregister --namespace "$1"
    ;;
  AZ-GOV-009)
    [ "$#" -eq 3 ] || { echo "Arguments: <resource-id> <ownership-tag-name> <owner-value>"; exit 1; }
    az tag update --resource-id "$1" --operation Merge --tags "$2=$3"
    ;;
  AZ-GOV-010)
    [ "$#" -eq 1 ] || { echo "Arguments: <subscription-id>"; exit 1; }
    az policy state trigger-scan --subscription "$1"
    ;;
  *)
    echo "Unsupported governance rule: $RULE_ID"
    exit 1
    ;;
esac
