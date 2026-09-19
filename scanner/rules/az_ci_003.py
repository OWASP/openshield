"""AZ-CI-003: Third-party workflow action not pinned to an immutable commit SHA."""

import logging
from typing import Any, Dict, List

from scanner.rules._workflow_common import (
    build_ci_finding,
    collect_uses,
    is_action_pinned,
    parse_workflow,
)

RULE_ID = "AZ-CI-003"
RULE_NAME = "Third-Party Workflow Action Not Pinned to Immutable Commit SHA"
SEVERITY = "HIGH"
CATEGORY = "CI/CD Security"
FRAMEWORKS = {
    "CIS": "N/A-CI-003",
    "NIST": "PR.IP-1",
    "ISO27001": "A.12.1.2",
    "SOC2": "CC7.1",
}
DESCRIPTION = (
    "One or more workflow steps reference a third-party action using a mutable tag or branch "
    "instead of a full 40-character commit SHA. A tag can be silently moved to point at "
    "malicious code, so any future run of the workflow would execute the attacker-controlled "
    "version without any change to the workflow file itself."
)
REMEDIATION = (
    "Pin every third-party action to a full commit SHA: "
    "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2\n"
    "Use a tool such as pin-github-action or Dependabot to keep pinned SHAs up to date. "
    "Local actions (./path) and Docker actions are exempt."
)
PLAYBOOK = "playbooks/cli/fix_az_ci_003.sh"
logger = logging.getLogger(__name__)


def scan(github_client: Any, owner: str, repo: str) -> List[Dict[str, Any]]:
    """Detect workflow steps that reference unpinned third-party actions."""
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
        unpinned = [uses for _, uses in collect_uses(parsed) if not is_action_pinned(uses)]
        if unpinned:
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
                    metadata={"unpinned_actions": unpinned},
                )
            )
    return findings
