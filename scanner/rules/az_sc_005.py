"""AZ-SC-005: Terraform state storage container is publicly readable."""

import logging
import re
from typing import Any, Dict, List

from scanner.evaluation import EVIDENCE_UNAVAILABLE, NO_RESOURCES_FOUND, EvaluationStatus, RuleEvaluation, fail_findings
from scanner.rules._supply_chain_common import (
    CONTAINER_TYPE,
    STORAGE_ACCOUNT_TYPE,
    evaluate_storage_accounts,
    evaluation,
    failed,
)

RULE_ID = "AZ-SC-005"
RULE_NAME = "Terraform State Storage Container Publicly Readable"
SEVERITY = "CRITICAL"
CATEGORY = "Supply Chain"
FRAMEWORKS = {"CIS": "N/A-SC-005", "NIST": "PR.AC-5", "ISO27001": "A.8.20", "SOC2": "CC6.6"}

DESCRIPTION = (
    "A blob container that appears to hold Terraform remote state (matched by name) allows "
    "public read access. Terraform state files commonly contain resource IDs, connection "
    "strings, and in some provider configurations plaintext secrets. Public read access on the "
    "state backend can expose the full infrastructure layout and any secrets it captured."
)

REMEDIATION = (
    "Set the container's public access level to Private and confirm no anonymous read policy is "
    "attached: az storage container set-permission --name <container> --account-name <account> "
    "--public-access off"
)

PLAYBOOK = "playbooks/cli/fix_az_sc_005.sh"

logger = logging.getLogger(__name__)

# Matches container names commonly used for a Terraform remote state backend,
# e.g. "tfstate", "terraform-state", "tf-state-prod".
_TFSTATE_NAME_PATTERN = re.compile(r"tf[-_]?state|terraform[-_]?state", re.IGNORECASE)


def _judge_account(
    azure_client: Any, account: Any, account_id: str, account_name: str, resource_group: str
) -> List[RuleEvaluation]:
    containers = azure_client.get_blob_containers(resource_group, account_name)
    if containers is None:
        logger.warning("%s: blob containers unknown for %s", RULE_ID, account_name)
        return [
            evaluation(
                RULE_ID,
                account_id,
                STORAGE_ACCOUNT_TYPE,
                EvaluationStatus.UNKNOWN,
                reason_code=EVIDENCE_UNAVAILABLE,
                reason="Blob containers could not be listed for the storage account.",
            )
        ]
    state_containers = [c for c in containers if _TFSTATE_NAME_PATTERN.search(getattr(c, "name", "") or "")]
    if not state_containers:
        return [
            evaluation(
                RULE_ID,
                account_id,
                STORAGE_ACCOUNT_TYPE,
                EvaluationStatus.NOT_APPLICABLE,
                reason_code=NO_RESOURCES_FOUND,
                reason="The storage account has no container named like a Terraform state backend.",
            )
        ]

    evaluations: List[RuleEvaluation] = []
    for container in state_containers:
        container_name = getattr(container, "name", "")
        container_id = f"{account_id}/blobServices/default/containers/{container_name}"
        props = getattr(container, "container_properties", None) or container
        public_access = str(getattr(props, "public_access", "") or "").lower()
        evidence = {"public_access": public_access or "none"}
        if public_access not in ("container", "blob"):
            evaluations.append(
                evaluation(RULE_ID, container_id, CONTAINER_TYPE, EvaluationStatus.PASS, evidence=evidence)
            )
            continue
        finding = {
            "rule_id": RULE_ID,
            "rule_name": RULE_NAME,
            "severity": SEVERITY,
            "category": CATEGORY,
            "resource_id": container_id,
            "resource_name": f"{account_name}/{container_name}",
            "resource_type": CONTAINER_TYPE,
            "description": DESCRIPTION,
            "remediation": REMEDIATION,
            "playbook": PLAYBOOK,
            "frameworks": FRAMEWORKS,
            "metadata": {
                "resource_group": resource_group,
                "storage_account": account_name,
                "container_name": container_name,
                "public_access": public_access,
            },
        }
        evaluations.append(failed(RULE_ID, finding, evidence))
    return evaluations


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return the findings attached to this rule's FAIL evaluations."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report a status for every Terraform-state-like blob container, per storage account."""
    return evaluate_storage_accounts(
        RULE_ID,
        azure_client,
        subscription_id,
        lambda account, account_id, name, resource_group: _judge_account(
            azure_client, account, account_id, name, resource_group
        ),
    )
