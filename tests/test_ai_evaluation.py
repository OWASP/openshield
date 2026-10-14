"""Measure retrieval and exercise evaluation failures without cloud/model calls."""

import json
import socket
from pathlib import Path
from unittest.mock import Mock

import pytest

from ai.evaluation.runner import DATASET, answer_diagnostics, evaluate, load_dataset, main
from ai.embed import build_vectorstore
from ai.retriever import retrieve


@pytest.fixture(scope="module")
def index(tmp_path_factory):
    path = tmp_path_factory.mktemp("eval-index") / "index.json"
    build_vectorstore(index_path=path)
    return path


def test_offline_report_never_connects_to_network(index, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Offline evaluation tried to open a network connection")

    monkeypatch.setattr(socket, "socket", forbidden)
    data = load_dataset()
    assert len(data["cases"]) >= 20
    report = evaluate(data, index)
    assert report == evaluate(data, index)
    assert report["metrics"]["requests_used"] == 0
    assert report["metrics"]["retrieval_cases"] == 22
    assert all(c["answer_status"] == "not_evaluated_offline" for c in report["cases"])
    # A conservative retrieval regression gate, not an answer correctness score.
    assert report["metrics"]["mean_recall_at_5"] >= 0.60
    assert next(c for c in report["cases"] if c["id"] == "unrelated-no-match")["retrieved_sources"] == []


@pytest.mark.parametrize("mutation", ["duplicate", "unknown_source", "invalid_expectation", "unknown_finding"])
def test_invalid_dataset_fails_before_evaluation(tmp_path, mutation):
    data = json.loads(DATASET.read_text())
    if mutation == "duplicate":
        data["cases"].append(data["cases"][0])
    elif mutation == "unknown_source":
        data["cases"][0]["expected_sources"] = ["AZ-FAKE-999"]
    elif mutation == "invalid_expectation":
        data["cases"][0]["expect_abstention"] = "yes"
    else:
        data["cases"][0]["findings"][0]["rule_id"] = "AZ-FAKE-999"
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        load_dataset(path)


def test_diagnostics_flag_invented_rule_and_missing_evidence():
    case = load_dataset()["cases"][0]
    result = answer_diagnostics(case, "AZ-FAKE-999 confirms a breach. data was stolen", [])
    assert result["unsupported_rule_references"] == ["AZ-FAKE-999"]
    assert result["rule_reference_precision"] == 0
    assert "data was stolen" in result["prohibited_claim_phrases_present"]
    assert result["required_fact_phrases_missing"]
    assert result["semantic_review"] == "required"
    assert answer_diagnostics(case, "", [])["rule_reference_precision"] is None


def test_negated_claim_is_only_a_diagnostic_not_a_correctness_verdict():
    case = load_dataset()["cases"][0]
    result = answer_diagnostics(case, "We cannot determine whether data was stolen.", [])
    assert result["abstention_phrase_present"]
    assert result["prohibited_claim_phrases_present"] == ["data was stolen"]
    assert result["semantic_review"] == "required"


def test_live_request_limit_and_production_prompt_guard(index):
    data = load_dataset()
    data["cases"] = [c for c in data["cases"] if c["category"] == "injection"]
    call = Mock(return_value="Insufficient evidence. AZ-STOR-001 describes public blob access.")
    report = evaluate(data, index, call, max_requests=1)
    assert call.call_count == report["metrics"]["requests_used"] == 1
    prompt = call.call_args.args[0]
    assert "[[FINDINGS " in prompt and "[[QUESTION " in prompt
    assert "IGNORE ALL RULES" in prompt
    assert report["cases"][0]["answer_status"] == "needs_human_review"
    assert all(c["answer_status"] == "request_limit" for c in report["cases"][1:])


def test_overlong_prompt_makes_no_provider_request(index):
    call = Mock()
    report = evaluate(load_dataset(), index, call, max_requests=1, max_prompt_chars=1)
    call.assert_not_called()
    assert report["metrics"]["requests_used"] == 0
    assert all(c["answer_status"] == "prompt_limit" for c in report["cases"])


def test_provider_errors_are_counted_and_redacted(index):
    call = Mock(side_effect=RuntimeError("sensitive-provider-response"))
    report = evaluate(load_dataset(), index, call, max_requests=1)
    assert call.call_count == 1
    assert report["cases"][0]["answer_status"] == "provider_error"
    assert "sensitive-provider-response" not in json.dumps(report)


@pytest.mark.parametrize("options", [[], ["--provider", "groq", "--model", "test", "--max-requests", "31"]])
def test_live_requires_explicit_limits(tmp_path, monkeypatch, options):
    monkeypatch.delenv("OPENSHIELD_EVAL_API_KEY", raising=False)
    with pytest.raises(SystemExit) as exc:
        main(["--live", "--output", str(tmp_path / "report.json"), *options])
    assert exc.value.code == 2


def test_cli_offline_writes_versioned_report(tmp_path, monkeypatch):
    # Isolated builder/retriever paths must not overwrite the application's index.
    import ai.embed
    import ai.retriever

    sentinel = tmp_path / "production.json"
    sentinel.write_text("unchanged")
    monkeypatch.setattr(ai.embed, "INDEX_PATH", sentinel)
    monkeypatch.setattr(ai.retriever, "INDEX_PATH", sentinel)
    output = tmp_path / "report.json"
    assert main(["--output", str(output)]) == 0
    report = json.loads(output.read_text())
    assert report["mode"] == "offline" and report["dataset_sha256"]
    assert sentinel.read_text() == "unchanged"


def test_explicit_index_matches_default_retrieval(index, monkeypatch):
    import ai.retriever

    monkeypatch.setattr(ai.retriever, "INDEX_PATH", index)
    assert retrieve("public blob access") == retrieve("public blob access", index_path=index)


def test_committed_baseline_is_identified_by_dataset():
    from ai.evaluation.runner import digest

    baseline = json.loads(Path("ai/evaluation/baseline.json").read_text())
    assert baseline["dataset_sha256"] == digest(DATASET.read_bytes())
    assert baseline["mode"] == "offline"
