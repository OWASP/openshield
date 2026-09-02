"""AZ-CI-002: CI/CD workflow has unnecessarily broad token permissions."""

import logging
from typing import Any, Dict, List

from scanner.rules._workflow_common import (
    build_ci_finding,
    get_top_level_permissions,
    is_permissions_broad,
    parse_workflow,
)

RULE_ID = "AZ-CI-002"
RULE_NAME = "CI/CD Workflow Has Unnecessarily Broad Token Permissions"
SEVERITY = "HIGH"
CATEGORY = "CI/CD Security"
FRAMEWORKS = {
    "CIS": "N/A-CI-002",
    "NIST": "PR.AC-4",
    "ISO27001": "A.9.2.3",
    "SOC2": "CC6.3",
}
DESCRIPTION = (
    "The workflow does not declare a top-level permissions block or declares write access "
    "to multiple sensitive scopes. Without an explicit permissions block the effective "
    "GITHUB_TOKEN permissions depend on the repository or organisation default, which "
    "OpenShield cannot read without repository metadata access. Over-broad permissions allow "
    "a compromised step to push code, modify releases, or exfiltrate secrets."
)

UNKNOWN_REASON = (
    "Cannot determine effective token permissions: the workflow has no explicit permissions "
    "block and the repository or organisation default permissions are not available. "
    "Set GITHUB_TOKEN permissions explicitly in the workflow to resolve this."
)
REMEDIATION = (
    "Add a top-level permissions block that grants only the minimum scopes required: "
    "permissions:\n  contents: read\n"
    "Override per-job only where broader access is needed. "
    "Never use permissions: write-all in production workflows."
)
PLAYBOOK = "playbooks/cli/fix_az_ci_002.sh"
logger = logging.getLogger(__name__)


def scan(github_client: Any, owner: str, repo: str) -> List[Dict[str, Any]]:
    """Detect workflows with broad or absent token permissions.

    When a workflow has no explicit permissions block, effective permissions
    depend on the repository or organisation default which we cannot read
    without additional API access. In that case the finding is emitted with
    severity MEDIUM and a note that the result is UNKNOWN until the default
    can be confirmed.
    """
    findings: List[Dict[str, Any]] = []
    workflows = github_client.get_workflows()
    if workflows is None:
        logger.warning("%s: workflows could not be enumerated for %s/%s", RULE_ID, owner, repo)
        return findings

    # Attempt to read repo default permissions (requires repo metadata)
    repo_info = github_client.get_repo_info()
    repo_default_permissions = None
    if repo_info is not None:
        # GitHub API exposes default_workflow_permissions on repo settings
        repo_default_permissions = repo_info.get("default_workflow_permissions")

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
        perms = get_top_level_permissions(parsed)

        if perms is None:
            # Check job-level permissions before deciding
            jobs = parsed.get("jobs") or {}
            all_jobs_explicit = jobs and all(
                isinstance(j, dict) and j.get("permissions") is not None for j in jobs.values()
            )
            if all_jobs_explicit and not is_permissions_broad(perms, parsed):
                # Every job declares explicit least-privilege permissions
                continue

            # No explicit permissions anywhere — check repo default
            if repo_default_permissions == "read":
                # Org/repo default is restricted — not broad, skip
                continue
            elif repo_default_permissions is None:
                # Cannot determine default — emit with UNKNOWN note
                findings.append(
                    build_ci_finding(
                        rule_id=RULE_ID,
                        rule_name=RULE_NAME,
                        severity="MEDIUM",
                        category=CATEGORY,
                        frameworks=FRAMEWORKS,
                        description=UNKNOWN_REASON,
                        remediation=REMEDIATION,
                        playbook=PLAYBOOK,
                        owner=owner,
                        repo=repo,
                        workflow_path=path,
                        metadata={
                            "permissions_declared": None,
                            "effective_permissions": "UNKNOWN",
                            "reason": "repo_default_permissions_unavailable",
                        },
                    )
                )
                continue

        if is_permissions_broad(perms, parsed):
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
                    metadata={"permissions_declared": perms},
                )
            )
    return findings
