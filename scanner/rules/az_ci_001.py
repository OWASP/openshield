"""AZ-CI-001: CI/CD workflow uses long-lived Azure credentials instead of workload identity federation."""

import logging
from typing import Any, Dict, List

from scanner.rules._workflow_common import (
    build_ci_finding,
    has_long_lived_credentials,
    parse_workflow,
    uses_workload_identity,
)

RULE_ID = "AZ-CI-001"
RULE_NAME = "CI/CD Workflow Uses Long-Lived Azure Credentials"
SEVERITY = "HIGH"
CATEGORY = "CI/CD Security"
FRAMEWORKS = {
    "CIS": "N/A-CI-001",
    "NIST": "PR.AC-1",
    "ISO27001": "A.9.2.4",
    "SOC2": "CC6.1",
}
DESCRIPTION = (
    "The workflow authenticates to Azure using a long-lived client secret or storage key "
    "stored as a repository secret. Long-lived credentials have no automatic expiry, cannot "
    "be scoped to a single workflow run, and grant persistent access if leaked. Workload "
    "identity federation (OIDC) issues short-lived tokens bound to the specific job context "
    "with no secret to store or rotate."
)
REMEDIATION = (
    "Replace the long-lived credential with workload identity federation: "
    "1. Register a federated identity credential on the Azure AD application or managed identity. "
    "2. Add permissions: id-token: write to the workflow. "
    "3. Use azure/login with client-id, tenant-id, subscription-id (no client-secret). "
    "4. Remove AZURE_CLIENT_SECRET and ARM_CLIENT_SECRET from repository secrets."
)
PLAYBOOK = "playbooks/cli/fix_az_ci_001.sh"
logger = logging.getLogger(__name__)


def scan(github_client: Any, owner: str, repo: str) -> List[Dict[str, Any]]:
    """Detect workflows that use long-lived Azure credentials."""
    findings: List[Dict[str, Any]] = []
    workflows = github_client.get_workflows()
    if workflows is None:
        logger.warning("%s: workflows could not be enumerated for %s/%s", RULE_ID, owner, repo)
        return findings
    for wf in workflows:
        path = wf.get("path", "")
        if not path:
            continue
        content = github_client.get_workflow_content(path)
        if content is None:
            logger.warning("%s: could not read %s", RULE_ID, path)
            continue
        parsed = parse_workflow(content)
        if parsed is None:
            continue
        creds = has_long_lived_credentials(content)
        # Only suppress if OIDC is present AND the specific credential is absent.
        # A workflow using OIDC but also referencing ARM_ACCESS_KEY still fails.
        if creds and not uses_workload_identity(content, parsed):
            findings.append(
                build_ci_finding(
                    rule_id=RULE_ID,
                    rule_name=RULE_NAME,
                    severity=SEVERITY,
                    category=CATEGORY,
                    frameworks=FRAMEWORKS,
                    description=DESCRIPTION,
                    remediation=REMEDIATION,
                    playbook=PLAYBOOK,
                    owner=owner,
                    repo=repo,
                    workflow_path=path,
                    metadata={"long_lived_credentials_found": creds},
                )
            )
    return findings
