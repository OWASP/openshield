"""CI/CD scan engine for GitHub workflow security rules (AZ-CI-*).

Runs AZ-CI-001..004 against a GitHub repository and returns
RuleEvaluation objects with PASS/FAIL/UNKNOWN status for each
workflow file, compatible with the existing evaluation contract
in scanner/evaluation.py.

Usage:
    from scanner.ci_engine import CIScanEngine
    engine = CIScanEngine(owner="my-org", repo="my-repo")
    results = engine.run_scan()
"""

import logging
from typing import List, Optional

import scanner.rules.az_ci_001 as az_ci_001
import scanner.rules.az_ci_002 as az_ci_002
import scanner.rules.az_ci_003 as az_ci_003
import scanner.rules.az_ci_004 as az_ci_004
from scanner.evaluation import EvaluationStatus, RuleEvaluation
from scanner.github_client import GitHubClient

logger = logging.getLogger(__name__)

_CI_RULES = [az_ci_001, az_ci_002, az_ci_003, az_ci_004]

RESOURCE_TYPE = "GitHub/WorkflowFile"


def _resource_id(owner: str, repo: str, workflow_path: str) -> str:
    """Canonical resource ID for a workflow file."""
    return f"github/{owner}/{repo}/workflows/{workflow_path}"


def _repo_scope_id(owner: str, repo: str) -> str:
    """Canonical resource ID when no workflows exist."""
    return f"github/{owner}/{repo}"


class CIScanEngine:
    """Runs AZ-CI-* rules against a GitHub repository.

    Each rule is run against every workflow file. Results are returned
    as RuleEvaluation objects with PASS/FAIL/UNKNOWN status.

    PASS   — workflow was evaluated and is compliant.
    FAIL   — workflow was evaluated and has a finding.
    UNKNOWN — workflow content could not be read or permissions
               could not be determined.
    """

    def __init__(
        self,
        owner: str,
        repo: str,
        token: Optional[str] = None,
    ) -> None:
        self.owner = owner
        self.repo = repo
        self.client = GitHubClient(owner=owner, repo=repo, token=token)

    def run_scan(self) -> List[RuleEvaluation]:
        """Run all AZ-CI-* rules and return RuleEvaluation results."""
        evaluations: List[RuleEvaluation] = []

        workflows = self.client.get_workflows()
        if workflows is None:
            # Cannot enumerate workflows — all rules return UNKNOWN
            for rule in _CI_RULES:
                evaluations.append(
                    RuleEvaluation(
                        rule_id=rule.RULE_ID,
                        resource_id=_repo_scope_id(self.owner, self.repo),
                        resource_type=RESOURCE_TYPE,
                        status=EvaluationStatus.UNKNOWN,
                        reason_code="WORKFLOWS_UNAVAILABLE",
                        reason=(
                            "GitHub API did not return workflow list. "
                            "Check GITHUB_TOKEN permissions (actions: read required)."
                        ),
                    )
                )
            return evaluations

        if not workflows:
            # Empty repo — not applicable
            for rule in _CI_RULES:
                evaluations.append(
                    RuleEvaluation(
                        rule_id=rule.RULE_ID,
                        resource_id=_repo_scope_id(self.owner, self.repo),
                        resource_type=RESOURCE_TYPE,
                        status=EvaluationStatus.NOT_APPLICABLE,
                        reason_code="NO_WORKFLOWS",
                        reason="Repository has no GitHub Actions workflow files.",
                    )
                )
            return evaluations

        # Pre-fetch and cache all workflow content once, keyed by path,
        # so each file is fetched exactly once instead of 4N times
        # (4 rules x N files). None means the content was unreadable.
        content_cache: dict = {}
        for wf in workflows:
            path = wf.get("path", "")
            if path and path not in content_cache:
                content_cache[path] = self.client.get_workflow_content(path)

        # Build a set of workflow paths that had findings per rule
        for rule in _CI_RULES:
            try:
                findings = rule.scan(self.client, self.owner, self.repo)
            except Exception as exc:
                logger.error("Error running rule %s: %s", rule.RULE_ID, exc)
                evaluations.append(
                    RuleEvaluation(
                        rule_id=rule.RULE_ID,
                        resource_id=_repo_scope_id(self.owner, self.repo),
                        resource_type=RESOURCE_TYPE,
                        status=EvaluationStatus.ERROR,
                        reason_code="RULE_EXCEPTION",
                        reason=f"Rule raised an exception: {exc}",
                    )
                )
                continue

            # Map findings to workflow paths
            finding_paths = {f.get("metadata", {}).get("workflow_path", "") for f in findings}
            # Emit one evaluation per workflow
            for wf in workflows:
                path = wf.get("path", "")
                if not path:
                    continue

                content = content_cache.get(path)
                if content is None:
                    evaluations.append(
                        RuleEvaluation(
                            rule_id=rule.RULE_ID,
                            resource_id=_resource_id(self.owner, self.repo, path),
                            resource_type=RESOURCE_TYPE,
                            status=EvaluationStatus.UNKNOWN,
                            reason_code="WORKFLOW_CONTENT_UNAVAILABLE",
                            reason=(
                                f"Workflow file {path} could not be read. "
                                "File may exceed 1 MB or token lacks contents: read."
                            ),
                        )
                    )
                    continue

                # Check if this workflow had an UNKNOWN finding (AZ-CI-002 emits these)
                unknown_finding = next(
                    (
                        f
                        for f in findings
                        if f.get("metadata", {}).get("workflow_path") == path
                        and f.get("metadata", {}).get("effective_permissions") == "UNKNOWN"
                    ),
                    None,
                )
                if unknown_finding:
                    evaluations.append(
                        RuleEvaluation(
                            rule_id=rule.RULE_ID,
                            resource_id=_resource_id(self.owner, self.repo, path),
                            resource_type=RESOURCE_TYPE,
                            status=EvaluationStatus.UNKNOWN,
                            reason_code="PERMISSIONS_DEFAULT_UNKNOWN",
                            reason=unknown_finding.get("description", ""),
                            evidence={"workflow_path": path},
                        )
                    )
                elif path in finding_paths:
                    # FAIL — workflow has a real finding
                    finding = next(
                        (f for f in findings if f.get("metadata", {}).get("workflow_path") == path),
                        None,
                    )
                    evaluations.append(
                        RuleEvaluation(
                            rule_id=rule.RULE_ID,
                            resource_id=_resource_id(self.owner, self.repo, path),
                            resource_type=RESOURCE_TYPE,
                            status=EvaluationStatus.FAIL,
                            reason_code="POLICY_VIOLATION",
                            reason=rule.RULE_NAME,
                            finding=finding,
                            evidence={"workflow_path": path},
                        )
                    )
                else:
                    # PASS — workflow was evaluated and is compliant
                    evaluations.append(
                        RuleEvaluation(
                            rule_id=rule.RULE_ID,
                            resource_id=_resource_id(self.owner, self.repo, path),
                            resource_type=RESOURCE_TYPE,
                            status=EvaluationStatus.PASS,
                            evidence={"workflow_path": path},
                        )
                    )

        return evaluations
