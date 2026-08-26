"""AZ-CI-004: Untrusted pull-request input reaches a privileged workflow context."""

import logging
from typing import Any, Dict, List

from scanner.rules._workflow_common import (
    build_ci_finding,
    get_dangerous_triggers,
    parse_workflow,
)

RULE_ID = "AZ-CI-004"
RULE_NAME = "Untrusted Pull-Request Input Reaches Privileged Workflow Context"
SEVERITY = "HIGH"
CATEGORY = "CI/CD Security"
FRAMEWORKS = {
    "CIS": "N/A-CI-004",
    "NIST": "PR.AC-4",
    "ISO27001": "A.14.2.5",
    "SOC2": "CC8.1",
}
DESCRIPTION = (
    "The workflow is triggered by pull_request_target or workflow_run, which run in the "
    "context of the base repository and have access to repository secrets and write "
    "permissions. If the workflow checks out or executes code from the pull request branch "
    "without explicit protection, an attacker can submit a malicious PR to exfiltrate "
    "secrets or push code — a pwn-request attack."
)
REMEDIATION = (
    "Never check out pull-request code in a pull_request_target workflow that also has "
    "secret access or write permissions. If both are needed, separate the privileged steps "
    "into a workflow triggered by workflow_run on a completed, already-vetted run. "
    "See: https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"
)
PLAYBOOK = "playbooks/cli/fix_az_ci_004.sh"
logger = logging.getLogger(__name__)

_PR_HEAD_REF_PATTERNS = (
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.ref",
    "github.head_ref",
    "GITHUB_HEAD_REF",
)


def _checks_out_pr_code(parsed: Dict[str, Any]) -> bool:
    """Return True if a checkout step ref: points to an untrusted PR head value.

    Uses the parsed workflow dict to avoid false positives from workflows
    that only reference head.sha in comments or non-checkout steps.
    """
    jobs = parsed.get("jobs") or {}
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses", "") or ""
            if "actions/checkout" not in uses:
                continue
            with_block = step.get("with") or {}
            ref_value = str(with_block.get("ref", "") or "")
            if any(p in ref_value for p in _PR_HEAD_REF_PATTERNS):
                return True
    return False


def scan(github_client: Any, owner: str, repo: str) -> List[Dict[str, Any]]:
    """Detect workflows where untrusted PR input reaches a privileged context."""
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
        dangerous = get_dangerous_triggers(parsed)
        if dangerous and _checks_out_pr_code(parsed):
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
                    metadata={"dangerous_triggers": dangerous},
                )
            )
    return findings
