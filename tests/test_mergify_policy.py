"""Static safety contracts for the committed queue policy, not a Mergify dry-run.

These tests parse the real configuration. They detect weakened gates and drift
between automatic entry and merging, but do not emulate Mergify events or prove
that GitHub review dismissal and queue operation work on an installed App.
"""

import re
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).parents[1]
CONFIG = yaml.safe_load((ROOT / ".mergify.yml").read_text(encoding="utf-8"))
QUEUE = CONFIG["queue_rules"][0]
RULES = CONFIG["pull_request_rules"]
ENTRY = next(rule for rule in RULES if "queue" in rule["actions"])
DISMISS = next(rule for rule in RULES if "dismiss_reviews" in rule["actions"])
STAGES = [ENTRY["conditions"], QUEUE["merge_conditions"]]


def _governance_gate(conditions):
    return next(
        condition["or"]
        for condition in conditions
        if isinstance(condition, dict) and "approved-reviews-by=Vishnu2707" in str(condition)
    )


@pytest.mark.parametrize("conditions", STAGES, ids=["entry", "merge"])
def test_summary_only_blocking_review_cannot_be_cleared_by_push(conditions):
    # No inline thread is needed: the review verdict has its own gate.
    assert "#changes-requested-reviews-by=0" in conditions
    assert DISMISS["actions"]["dismiss_reviews"]["changes_requested"] is False


def test_contributor_push_dismisses_approvals_but_queue_rebase_is_exempt():
    assert DISMISS["actions"]["dismiss_reviews"]["approved"] is True
    assert DISMISS["conditions"] == ["base=dev", "sender!=mergify[bot]"]


@pytest.mark.parametrize("conditions", STAGES, ids=["entry", "merge"])
def test_fresh_approval_and_resolved_threads_are_required(conditions):
    assert "#approved-reviews-by>=1" in conditions
    assert "#review-threads-unresolved=0" in conditions


@pytest.mark.parametrize("conditions", STAGES, ids=["entry", "merge"])
@pytest.mark.parametrize("path", ["GOVERNANCE.md", "MAINTAINERS.md", ".mergify.yml", "docs/merge-queue.md"])
def test_each_governed_path_requires_two_approvals_including_lead(conditions, path):
    exemption, approval_gate = _governance_gate(conditions)
    assert exemption.startswith("-files~=")
    assert re.search(exemption.removeprefix("-files~="), path)
    assert set(approval_gate["and"]) == {"#approved-reviews-by>=2", "approved-reviews-by=Vishnu2707"}


@pytest.mark.parametrize("conditions", STAGES, ids=["entry", "merge"])
def test_ordinary_paths_do_not_trigger_governance_exception(conditions):
    exemption, _ = _governance_gate(conditions)
    pattern = exemption.removeprefix("-files~=")
    for path in ["scanner/engine.py", "docs/merge-queue.md.bak", "nested/GOVERNANCE.md"]:
        assert re.search(pattern, path) is None


def test_automatic_entry_and_merge_have_identical_checks_and_review_gates():
    assert ENTRY["conditions"] == ["base=dev", *QUEUE["merge_conditions"]]
    assert ENTRY["actions"]["queue"]["name"] == QUEUE["name"]
    assert QUEUE["queue_conditions"] == ["base=dev", "-draft", "-label=blocked"]


@pytest.mark.parametrize("conditions", STAGES, ids=["entry", "merge"])
def test_terraform_check_is_required_only_for_terraform_changes(conditions):
    check = "check-success=Terraform fmt / validate / plan"
    assert check not in conditions  # Non-Terraform PRs must not wait on an absent job.
    assert {"or": ["-files~=^infra/terraform/", check]} in conditions
    pattern = "^infra/terraform/"
    assert re.search(pattern, "infra/terraform/main.tf")
    assert re.search(pattern, "frontend/src/main.jsx") is None


def test_required_ci_checks_and_serial_queue_are_preserved():
    expected = {
        "check-success=CI Summary",
        "check-success=DCO sign-off",
        "check-success=dependency-review",
        "check-success=Analyze (python)",
        "check-success=Analyze (javascript)",
    }
    assert expected <= {condition for condition in QUEUE["merge_conditions"] if isinstance(condition, str)}
    assert CONFIG["merge_queue"]["max_parallel_checks"] == 1
    assert QUEUE["batch_size"] == 1
    for stage in STAGES:
        assert "-draft" in stage
        assert "-label=blocked" in stage
