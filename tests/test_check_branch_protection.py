"""Tests for the branch-protection drift audit (issue #298)."""

import copy
import json
from pathlib import Path

import pytest
import yaml

from scripts import check_branch_protection as audit

REPO_ROOT = Path(__file__).parents[1]
CONFIG_DIR = REPO_ROOT / ".github" / "branch-protection"


def _declared(branch):
    return audit.load_expected(CONFIG_DIR, branch)


def _effective_from_declared(branch, ruleset_id=7):
    """Rules as GET /rules/branches/{branch} reports them when fully applied."""
    rules = copy.deepcopy(_declared(branch)["rules"])
    for rule in rules:
        rule["ruleset_source_type"] = "Repository"
        rule["ruleset_id"] = ruleset_id
    return rules


def _fetcher(rules_by_branch, ruleset_detail=None):
    detail = ruleset_detail if ruleset_detail is not None else {"id": 7, "name": "protection", "bypass_actors": []}

    def fetch(path):
        if "/rules/branches/" in path:
            return rules_by_branch[path.rsplit("/", 1)[1]]
        if "/rulesets/" in path:
            return detail
        if "/branches/" in path:
            return {"protection": {"enabled": True, "required_status_checks": {"enforcement_level": "off"}}}
        raise AssertionError(f"unexpected path {path}")

    return fetch


@pytest.mark.parametrize("branch", ["dev", "main"])
def test_committed_rulesets_are_valid(branch):
    assert audit.validate_declared(branch, _declared(branch)) == []


def test_main_requires_two_person_review_and_dev_one():
    def approvals(branch):
        rule = next(r for r in _declared(branch)["rules"] if r["type"] == "pull_request")
        return rule["parameters"]["required_approving_review_count"]

    assert approvals("dev") >= 1
    assert approvals("main") >= 2


@pytest.mark.parametrize("branch", ["dev", "main"])
def test_required_checks_match_real_workflow_job_names(branch):
    workflows = REPO_ROOT / ".github" / "workflows"
    names = set()
    for path in workflows.glob("*.yml"):
        for job_id, job in (yaml.safe_load(path.read_text(encoding="utf-8")).get("jobs") or {}).items():
            name = job.get("name", job_id)
            languages = ((job.get("strategy") or {}).get("matrix") or {}).get("language")
            if languages and "${{ matrix.language }}" in name:
                names.update(name.replace("${{ matrix.language }}", lang) for lang in languages)
            else:
                names.add(name)

    rule = next(r for r in _declared(branch)["rules"] if r["type"] == "required_status_checks")
    missing = [c["context"] for c in rule["parameters"]["required_status_checks"] if c["context"] not in names]
    assert missing == [], "required checks must name jobs that actually run, or merges block forever"


def test_declared_validation_rejects_weakened_rulesets():
    ruleset = _declared("main")
    ruleset["bypass_actors"] = [{"actor_type": "OrganizationAdmin", "actor_id": 1, "bypass_mode": "always"}]
    for rule in ruleset["rules"]:
        if rule["type"] == "pull_request":
            rule["parameters"]["required_approving_review_count"] = 1
            rule["parameters"]["require_last_push_approval"] = False
        if rule["type"] == "required_status_checks":
            rule["parameters"]["strict_required_status_checks_policy"] = False

    problems = audit.validate_declared("main", ruleset)
    assert any("bypass" in p for p in problems)
    assert any("fewer than 2 approvals" in p for p in problems)
    assert any("require_last_push_approval" in p for p in problems)
    assert any("strict" in p for p in problems)


def test_fully_applied_rules_are_compliant():
    record = audit.audit_branch("o/r", "main", _declared("main"), _fetcher({"main": _effective_from_declared("main")}))
    assert record["compliant"] is True
    assert record["problems"] == []


def test_unprotected_branch_is_reported_as_drift():
    """The state observed on 2026-08-21: protected flag set but no rules enforced."""
    record = audit.audit_branch("o/r", "dev", _declared("dev"), _fetcher({"dev": []}))
    assert record["compliant"] is False
    assert "dev: 'required_status_checks' rule is not enforced" in record["problems"]
    assert "dev: 'pull_request' rule is not enforced" in record["problems"]


def test_missing_check_non_strict_and_self_approval_are_drift():
    rules = _effective_from_declared("main")
    for rule in rules:
        if rule["type"] == "required_status_checks":
            rule["parameters"]["strict_required_status_checks_policy"] = False
            rule["parameters"]["required_status_checks"] = [
                c for c in rule["parameters"]["required_status_checks"] if c["context"] != "CI Summary"
            ]
        if rule["type"] == "pull_request":
            rule["parameters"]["required_approving_review_count"] = 1
            rule["parameters"]["require_last_push_approval"] = False

    problems = audit.compare_effective("main", _declared("main"), rules)
    assert "main: required status check 'CI Summary' is not enforced" in problems
    assert "main: status checks are not strict; a stale head can merge" in problems
    assert "main: requires 1 approving review(s), expected at least 2" in problems
    assert "main: pull_request rule does not enforce require_last_push_approval" in problems


def test_standing_bypass_actor_is_drift():
    detail = {
        "id": 7,
        "name": "main",
        "bypass_actors": [{"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"}],
    }
    record = audit.audit_branch(
        "o/r", "main", _declared("main"), _fetcher({"main": _effective_from_declared("main")}, detail)
    )
    assert record["compliant"] is False
    assert any("standing bypass" in p for p in record["problems"])


def test_hidden_bypass_actors_are_unverified_not_compliant_evidence():
    detail = {"id": 7, "name": "main"}
    record = audit.audit_branch(
        "o/r", "main", _declared("main"), _fetcher({"main": _effective_from_declared("main")}, detail)
    )
    assert record["compliant"] is True
    assert any("unverified" in note for note in record["notes"])


def test_main_writes_evidence_and_fails_on_drift(tmp_path, capsys):
    evidence = tmp_path / "evidence.json"
    fetch = _fetcher({"dev": _effective_from_declared("dev"), "main": []})

    code = audit.main(["--repo", "o/r", "--evidence", str(evidence)], fetch=fetch)

    assert code == 1
    record = json.loads(evidence.read_text(encoding="utf-8"))
    assert record["compliant"] is False
    assert [b["branch"] for b in record["branches"]] == ["dev", "main"]
    assert "[DRIFT] o/r@main" in capsys.readouterr().out


def test_validate_only_does_not_call_the_api():
    def fetch(_path):
        raise AssertionError("validate-only must stay offline")

    assert audit.main(["--validate-only"], fetch=fetch) == 0


def test_classic_protection_is_noted_but_not_counted_as_enforcement():
    record = audit.audit_branch("o/r", "dev", _declared("dev"), _fetcher({"dev": []}))
    assert record["compliant"] is False
    assert any("classic branch protection is enabled (status-check enforcement: off)" in n for n in record["notes"])


def test_unreachable_api_fails_closed(capsys):
    def fetch(_path):
        raise OSError("offline")

    assert audit.main(["--repo", "o/r"], fetch=fetch) == 1
    assert "GitHub API unreachable" in capsys.readouterr().out


def test_api_error_status_fails_closed(capsys):
    def fetch(_path):
        raise audit.GitHubApiError(403)

    assert audit.main(["--repo", "o/r", "--branch", "dev"], fetch=fetch) == 1
    assert "GitHub API error 403" in capsys.readouterr().out
