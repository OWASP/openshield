"""Compare effective GitHub branch rules against the versioned rulesets.

The desired protection for ``dev`` and ``main`` lives in
``.github/branch-protection/<branch>.json`` in GitHub's repository-ruleset
import format. This script reads the rules GitHub actually enforces on each
branch and fails when they are weaker than that declared state, so protection
is demonstrated by an automated assertion rather than by documentation alone.

Usage:
    python scripts/check_branch_protection.py --validate-only
    GITHUB_TOKEN=... python scripts/check_branch_protection.py \\
        --repo OWASP/openshield --evidence branch-protection-evidence.json

``--validate-only`` checks the declared rulesets offline. Without it the script
queries the GitHub REST API. ``GET /repos/{repo}/rules/branches/{branch}`` is
readable with a read-only token; ruleset bypass actors are only returned to
tokens that can administer rulesets, so when they are hidden the script
reports them as unverified instead of treating them as compliant.
"""

import argparse
import json
import os
import ssl
import sys
import http.client
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_DIR = REPO_ROOT / ".github" / "branch-protection"
DEFAULT_BRANCHES = ("dev", "main")
API_HOST = "api.github.com"

# Promotion to main must never be approvable by its own author alone.
MIN_APPROVALS = {"dev": 1, "main": 2}
REQUIRED_RULE_TYPES = ("deletion", "non_fast_forward", "pull_request", "required_status_checks")
PULL_REQUEST_FLAGS = (
    "dismiss_stale_reviews_on_push",
    "require_code_owner_review",
    "require_last_push_approval",
    "required_review_thread_resolution",
)

Fetcher = Callable[[str], Any]


def load_expected(config_dir: Path, branch: str) -> Dict[str, Any]:
    """Load the declared ruleset for ``branch``."""
    with open(config_dir / f"{branch}.json", encoding="utf-8") as handle:
        return json.load(handle)


def _rules_by_type(rules: List[Dict[str, Any]], rule_type: str) -> List[Dict[str, Any]]:
    return [rule for rule in rules if rule.get("type") == rule_type]


def _required_contexts(rule: Dict[str, Any]) -> List[str]:
    checks = (rule.get("parameters") or {}).get("required_status_checks") or []
    return [check.get("context", "") for check in checks]


def validate_declared(branch: str, ruleset: Dict[str, Any]) -> List[str]:
    """Return problems in a declared ruleset; an empty list means it is valid."""
    problems: List[str] = []
    if ruleset.get("target") != "branch":
        problems.append(f"{branch}: ruleset target must be 'branch'")
    if ruleset.get("enforcement") != "active":
        problems.append(f"{branch}: ruleset enforcement must be 'active'")
    if ruleset.get("bypass_actors"):
        problems.append(f"{branch}: declared ruleset must not grant standing bypass actors")
    include = ((ruleset.get("conditions") or {}).get("ref_name") or {}).get("include") or []
    if f"refs/heads/{branch}" not in include:
        problems.append(f"{branch}: ruleset does not target refs/heads/{branch}")

    rules = ruleset.get("rules") or []
    for rule_type in REQUIRED_RULE_TYPES:
        if not _rules_by_type(rules, rule_type):
            problems.append(f"{branch}: declared ruleset is missing the '{rule_type}' rule")

    for rule in _rules_by_type(rules, "pull_request"):
        params = rule.get("parameters") or {}
        if params.get("required_approving_review_count", 0) < MIN_APPROVALS.get(branch, 1):
            problems.append(f"{branch}: declared ruleset requires fewer than {MIN_APPROVALS.get(branch, 1)} approvals")
        for flag in PULL_REQUEST_FLAGS:
            if params.get(flag) is not True:
                problems.append(f"{branch}: declared pull_request rule must set {flag}")

    for rule in _rules_by_type(rules, "required_status_checks"):
        params = rule.get("parameters") or {}
        if params.get("strict_required_status_checks_policy") is not True:
            problems.append(f"{branch}: declared status checks must be strict (up to date before merge)")
        if "CI Summary" not in _required_contexts(rule):
            problems.append(f"{branch}: declared status checks must include 'CI Summary'")
    return problems


def compare_effective(
    branch: str,
    expected: Dict[str, Any],
    effective_rules: List[Dict[str, Any]],
) -> List[str]:
    """Return every way the effective branch rules are weaker than declared."""
    problems: List[str] = []
    expected_rules = expected.get("rules") or []

    for rule_type in REQUIRED_RULE_TYPES:
        if _rules_by_type(expected_rules, rule_type) and not _rules_by_type(effective_rules, rule_type):
            problems.append(f"{branch}: '{rule_type}' rule is not enforced")

    effective_pr = [rule.get("parameters") or {} for rule in _rules_by_type(effective_rules, "pull_request")]
    for rule in _rules_by_type(expected_rules, "pull_request"):
        params = rule.get("parameters") or {}
        if not effective_pr:
            break
        wanted = params.get("required_approving_review_count", 0)
        actual = max(p.get("required_approving_review_count", 0) for p in effective_pr)
        if actual < wanted:
            problems.append(f"{branch}: requires {actual} approving review(s), expected at least {wanted}")
        for flag in PULL_REQUEST_FLAGS:
            if params.get(flag) and not any(p.get(flag) for p in effective_pr):
                problems.append(f"{branch}: pull_request rule does not enforce {flag}")

    effective_checks = _rules_by_type(effective_rules, "required_status_checks")
    enforced_contexts = {context for rule in effective_checks for context in _required_contexts(rule)}
    strict = any(
        (rule.get("parameters") or {}).get("strict_required_status_checks_policy") for rule in effective_checks
    )
    for rule in _rules_by_type(expected_rules, "required_status_checks"):
        if not effective_checks:
            break
        for context in _required_contexts(rule):
            if context not in enforced_contexts:
                problems.append(f"{branch}: required status check '{context}' is not enforced")
        if (rule.get("parameters") or {}).get("strict_required_status_checks_policy") and not strict:
            problems.append(f"{branch}: status checks are not strict; a stale head can merge")
    return problems


def audit_bypass(branch: str, rulesets: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    """Return (problems, notes) about bypass actors on the rulesets in force."""
    problems: List[str] = []
    notes: List[str] = []
    for ruleset in rulesets:
        name = ruleset.get("name", ruleset.get("id"))
        if "bypass_actors" not in ruleset:
            notes.append(f"{branch}: bypass actors on ruleset '{name}' are not visible to this token (unverified)")
        elif ruleset["bypass_actors"]:
            actors = ", ".join(
                f"{actor.get('actor_type')}:{actor.get('actor_id')}({actor.get('bypass_mode')})"
                for actor in ruleset["bypass_actors"]
            )
            problems.append(f"{branch}: ruleset '{name}' grants standing bypass to {actors}")
    return problems, notes


class GitHubApiError(Exception):
    """The GitHub API returned a non-success status."""

    def __init__(self, status: int) -> None:
        super().__init__(f"GitHub API returned HTTP {status}")
        self.status = status


def github_fetcher(token: Optional[str]) -> Fetcher:
    """Return a JSON GET helper bound to the GitHub REST API host.

    The host and scheme are fixed; only the request path varies, so a crafted
    value can never redirect the request to another host or a file:// URL.
    """

    def fetch(path: str) -> Any:
        if not path.startswith("/"):
            raise ValueError(f"API path must be absolute: {path!r}")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "openshield-branch-protection-audit",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        # Fixed host with certificate and hostname verification from the default context.
        connection = http.client.HTTPSConnection(  # nosemgrep: python.lang.security.audit.httpsconnection-detected.httpsconnection-detected  # noqa: E501
            API_HOST, timeout=30, context=ssl.create_default_context()
        )
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            body = response.read()
        finally:
            connection.close()
        if response.status >= 400:
            raise GitHubApiError(response.status)
        return json.loads(body)

    return fetch


def audit_branch(repo: str, branch: str, expected: Dict[str, Any], fetch: Fetcher) -> Dict[str, Any]:
    """Audit one branch and return its evidence record."""
    effective_rules = fetch(f"/repos/{repo}/rules/branches/{branch}") or []
    problems = compare_effective(branch, expected, effective_rules)

    ruleset_ids = sorted({rule["ruleset_id"] for rule in effective_rules if rule.get("ruleset_id") is not None})
    rulesets = [fetch(f"/repos/{repo}/rulesets/{ruleset_id}") for ruleset_id in ruleset_ids]
    bypass_problems, notes = audit_bypass(branch, rulesets)
    problems.extend(bypass_problems)

    # Classic branch protection is not reported by the rules API. Record what
    # the branch summary exposes so the evidence shows it, but only rulesets
    # count as the declared, auditable state.
    classic = (fetch(f"/repos/{repo}/branches/{branch}") or {}).get("protection") or {}
    if classic.get("enabled"):
        level = (classic.get("required_status_checks") or {}).get("enforcement_level", "unknown")
        notes.append(
            f"{branch}: classic branch protection is enabled (status-check enforcement: {level}); "
            "it is not auditable here and should be replaced by the declared ruleset"
        )

    return {
        "branch": branch,
        "compliant": not problems,
        "problems": problems,
        "notes": notes,
        "effective_rules": effective_rules,
        "ruleset_ids": ruleset_ids,
    }


def main(argv: Optional[List[str]] = None, fetch: Optional[Fetcher] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "OWASP/openshield"))
    parser.add_argument("--branch", action="append", dest="branches", help="branch to audit (repeatable)")
    parser.add_argument("--config-dir", type=Path, default=DEFAULT_CONFIG_DIR)
    parser.add_argument("--evidence", type=Path, help="write a JSON evidence record to this path")
    parser.add_argument("--validate-only", action="store_true", help="only validate the declared rulesets")
    args = parser.parse_args(argv)

    branches = args.branches or list(DEFAULT_BRANCHES)
    declared_problems: List[str] = []
    expected: Dict[str, Dict[str, Any]] = {}
    for branch in branches:
        try:
            expected[branch] = load_expected(args.config_dir, branch)
        except (OSError, json.JSONDecodeError) as exc:
            declared_problems.append(f"{branch}: cannot load declared ruleset: {exc}")
            continue
        declared_problems.extend(validate_declared(branch, expected[branch]))

    if declared_problems:
        for problem in declared_problems:
            print(f"DECLARED: {problem}")
        return 1
    if args.validate_only:
        print(f"Declared rulesets are valid for: {', '.join(branches)}")
        return 0

    fetch = fetch or github_fetcher(os.environ.get("GITHUB_TOKEN"))
    records = []
    for branch in branches:
        try:
            records.append(audit_branch(args.repo, branch, expected[branch], fetch))
        except GitHubApiError as exc:
            records.append(
                {"branch": branch, "compliant": False, "problems": [f"{branch}: GitHub API error {exc.status}"]}
            )
        except (OSError, http.client.HTTPException, ValueError) as exc:
            # An unreachable API or unreadable response is not evidence of
            # protection: fail closed.
            records.append(
                {"branch": branch, "compliant": False, "problems": [f"{branch}: GitHub API unreachable: {exc}"]}
            )

    compliant = all(record["compliant"] for record in records)
    for record in records:
        status = "OK" if record["compliant"] else "DRIFT"
        print(f"[{status}] {args.repo}@{record['branch']}")
        for problem in record["problems"]:
            print(f"  - {problem}")
        for note in record.get("notes", []):
            print(f"  ! {note}")

    if args.evidence:
        evidence = {
            "repository": args.repo,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "compliant": compliant,
            "branches": records,
        }
        args.evidence.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

    return 0 if compliant else 1


if __name__ == "__main__":
    sys.exit(main())
