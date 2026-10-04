"""AZ-STOR-010: Storage account reachable publicly with no approved private endpoint."""

import logging
from typing import Any, Dict, List

from scanner.azure_client import enum_str
from scanner.evaluation import (
    EVIDENCE_UNAVAILABLE,
    EvaluationStatus,
    RuleEvaluation,
    fail_findings,
    inventory_unavailable,
    missing_resource_id,
    no_resources_found,
)

logger = logging.getLogger(__name__)

RULE_ID = "AZ-STOR-010"
RULE_NAME = "Storage Account Missing Private Endpoint"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {"CIS": "N/A-STOR-010", "NIST": "PR.AC-5", "ISO27001": "A.8.22", "SOC2": "CC6.6"}
DESCRIPTION = (
    "A storage account reachable over the public network has no approved Private "
    "Endpoint connection, so its blob/file/queue/table endpoints stay reachable from "
    "the internet. Traffic does not remain inside a private VNet, widening the attack "
    "surface for unauthorized access and data exfiltration."
)
REMEDIATION = (
    "Create a Private Endpoint for the storage account and approve the connection "
    "(`az network private-endpoint create ...`), then set the account's public network "
    "access to Disabled (or Selected networks) so traffic flows only over the private "
    "IP inside the VNet."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_010.sh"
RESOURCE_TYPE = "Microsoft.Storage/storageAccounts"


def _has_approved_private_endpoint(connections: Any) -> bool:
    """True if any Private Endpoint connection in the list is in the Approved state."""
    for connection in connections or []:
        state = getattr(connection, "private_link_service_connection_state", None)
        if enum_str(getattr(state, "status", None)).lower() == "approved":
            return True
    return False


def _finding(account: Any, connections: Any) -> Dict[str, Any]:
    return {
        "rule_id": RULE_ID,
        "rule_name": RULE_NAME,
        "severity": SEVERITY,
        "category": CATEGORY,
        "resource_id": getattr(account, "id", ""),
        "resource_name": getattr(account, "name", ""),
        "resource_type": "Microsoft.Storage/storageAccounts",
        "description": DESCRIPTION,
        "remediation": REMEDIATION,
        "playbook": PLAYBOOK,
        "frameworks": FRAMEWORKS,
        "metadata": {
            "public_network_access": enum_str(getattr(account, "public_network_access", None)) or "unspecified",
            "private_endpoint_connections": len(connections),
        },
    }


def _evaluate_account(azure_client: Any, account: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Fail publicly reachable storage accounts with no approved Private Endpoint.

    A storage account whose ``public_network_access`` is already ``Disabled`` is
    network-isolated regardless of private endpoints and is NOT_APPLICABLE, so
    the rule does not raise a false finding against an account that is closed
    to the public network by another means.

    ``private_endpoint_connections`` of ``None`` means the evidence is
    unavailable (the field was not populated / could not be read), not a
    confirmed absence, so the account is UNKNOWN rather than failed. Only a
    genuine empty list (or connections with none Approved) is a FAIL.
    """
    if not getattr(account, "id", None):
        return [missing_resource_id(RULE_ID, RESOURCE_TYPE, subscription_id)]
    public_access = enum_str(getattr(account, "public_network_access", None))
    if public_access.lower() == "disabled":
        return [
            _evaluation(
                account.id,
                EvaluationStatus.NOT_APPLICABLE,
                reason_code="PUBLIC_ACCESS_DISABLED",
                reason="Public network access is disabled on the storage account.",
            )
        ]

    connections = getattr(account, "private_endpoint_connections", None)
    if connections is None:
        logger.warning(
            "AZ-STOR-010: private endpoint connections unavailable for %s — reporting UNKNOWN",
            getattr(account, "name", ""),
        )
        return [
            _evaluation(
                account.id,
                EvaluationStatus.UNKNOWN,
                reason_code=EVIDENCE_UNAVAILABLE,
                reason="Private endpoint connections were not returned for the storage account.",
            )
        ]
    evidence = {
        "public_network_access": public_access or "unspecified",
        "private_endpoint_connections": len(connections),
    }
    if _has_approved_private_endpoint(connections):
        return [_evaluation(account.id, EvaluationStatus.PASS, evidence=evidence)]
    return [_evaluation(account.id, EvaluationStatus.FAIL, evidence=evidence, finding=_finding(account, connections))]


def _evaluation(resource_id: str, status: str, **kwargs: Any) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=RULE_ID, resource_id=resource_id, resource_type=RESOURCE_TYPE, status=status, **kwargs
    )


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return the findings attached to this rule's FAIL evaluations."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report a status for every storage account, PASS included."""
    accounts = azure_client.list_storage_accounts()
    if accounts is None:
        return [inventory_unavailable(RULE_ID, RESOURCE_TYPE, subscription_id)]
    if not accounts:
        return [no_resources_found(RULE_ID, RESOURCE_TYPE, subscription_id)]
    evaluations: List[RuleEvaluation] = []
    for account in accounts:
        evaluations.extend(_evaluate_account(azure_client, account, subscription_id))
    return evaluations
