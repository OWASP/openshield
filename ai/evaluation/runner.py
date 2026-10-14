"""Run with python -m ai.evaluation.runner; no network in offline mode."""

import argparse
import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from ai.embed import build_vectorstore
from ai.loader import load_rule_documents
from ai.retriever import retrieve

DATASET = Path(__file__).with_name("cases.json")
PROMPT_VERSION = "evaluation-ask-v1"
RULE_ID = re.compile(r"\bAZ-[A-Z]+-\d{3}\b")
ABSTENTION = re.compile(r"insufficient|cannot determine|not enough|missing evidence|not in (?:the )?knowledge", re.I)


def digest(data: bytes) -> str:
    """Identify the exact dataset or index used by a run."""
    return hashlib.sha256(data).hexdigest()


def load_dataset(path: Path = DATASET) -> dict[str, Any]:
    """Reject malformed fixtures and references to nonexistent scanner rules."""
    dataset = json.loads(path.read_text(encoding="utf-8"))
    if dataset.get("version") != "1" or not isinstance(dataset.get("cases"), list) or not dataset["cases"]:
        raise ValueError("Expected a nonempty version 1 dataset")
    known = {d["metadata"]["rule_id"] for d in load_rule_documents()}
    seen = set()
    for case in dataset["cases"]:
        if not isinstance(case.get("id"), str) or not case["id"] or case["id"] in seen:
            raise ValueError("Case IDs must be nonempty and unique")
        seen.add(case["id"])
        for key in ("question", "category"):
            if not isinstance(case.get(key), str) or not case[key].strip():
                raise ValueError(f"{case['id']}: {key} must be nonempty text")
        for key in ("expected_sources", "required_facts", "prohibited_claims"):
            if not isinstance(case.get(key), list) or any(not isinstance(v, str) or not v for v in case[key]):
                raise ValueError(f"{case['id']}: invalid {key}")
        if not isinstance(case.get("expect_abstention"), bool) or not isinstance(case.get("findings"), list):
            raise ValueError(f"{case['id']}: invalid evidence or abstention expectation")
        for source in case["expected_sources"]:
            if source not in known:
                raise ValueError(f"{case['id']}: unknown expected rule {source}")
        for finding in case["findings"]:
            if not isinstance(finding, dict) or finding.get("rule_id") not in known:
                raise ValueError(f"{case['id']}: unknown finding rule")
            if not isinstance(finding.get("resource_name"), str) or not finding["resource_name"]:
                raise ValueError(f"{case['id']}: missing resource name")
    return dataset


def answer_diagnostics(case: dict[str, Any], answer: str, sources: list[dict]) -> dict[str, Any]:
    """Mechanical warning signals, never a semantic correctness score."""
    allowed_rules = {f["rule_id"] for f in case["findings"]} | {
        s["source_meta"]["id"] for s in sources if s["source_meta"].get("type") == "openShield_rule"
    }
    mentioned = set(RULE_ID.findall(answer))
    resources = {f["resource_name"] for f in case["findings"]}
    lower = answer.lower()
    return {
        "unsupported_rule_references": sorted(mentioned - allowed_rules),
        "referenced_rule_count": len(mentioned),
        "rule_reference_precision": len(mentioned & allowed_rules) / len(mentioned) if mentioned else None,
        "expected_resources_mentioned": sorted(r for r in resources if r in answer),
        "expected_resource_mention_rate": sum(r in answer for r in resources) / len(resources) if resources else None,
        "required_fact_phrases_missing": [p for p in case["required_facts"] if p.lower() not in lower],
        "prohibited_claim_phrases_present": [p for p in case["prohibited_claims"] if p.lower() in lower],
        "abstention_expected": case["expect_abstention"],
        "abstention_phrase_present": bool(ABSTENTION.search(answer)),
        "semantic_review": "required",
    }


def evaluate(
    dataset: dict[str, Any],
    index_path: Path,
    completion: Callable[[str], str] | None = None,
    max_requests: int = 0,
    max_prompt_chars: int = 16000,
) -> dict[str, Any]:
    """Measure actual retrieval; optionally call the production ask prompt/provider."""
    rows = []
    requests_used = 0
    for case in dataset["cases"]:
        sources = retrieve(case["question"], n_results=5, index_path=index_path)
        actual = {s["source_meta"]["id"] for s in sources}
        expected = set(case["expected_sources"])
        row = {
            "id": case["id"],
            "category": case["category"],
            "expected_sources": sorted(expected),
            "retrieved_sources": [s["source"] for s in sources],
            "recall_at_5": len(expected & actual) / len(expected) if expected else None,
            "expected_abstention": case["expect_abstention"],
            "answer_status": "not_evaluated_offline" if completion is None else "request_limit",
        }
        if completion is not None and requests_used < max_requests:
            # Import only for explicit live mode. These are the existing application's prompt and input guard.
            from api.routes.ai import _build_ask_prompt
            from api.services.ai_guard import finding_record, new_boundary

            context = "\n".join(f"- ({s['source']}) {s['text']}" for s in sources)
            records = [finding_record(f) for f in case["findings"]]
            prompt = _build_ask_prompt(records, context, case["question"], new_boundary())
            if len(prompt) > max_prompt_chars:
                row["answer_status"] = "prompt_limit"
            else:
                requests_used += 1
                started = time.monotonic()
                try:
                    answer = completion(prompt)
                    row.update(
                        answer_status="needs_human_review",
                        answer=answer,
                        diagnostics=answer_diagnostics(case, answer, sources),
                    )
                except Exception:
                    # Provider exceptions may contain credentials or response bodies. Never persist them.
                    row["answer_status"] = "provider_error"
                row["latency_seconds"] = round(time.monotonic() - started, 3)
                row["prompt_sha256"] = digest(prompt.encode())
        rows.append(row)
    recalls = [r["recall_at_5"] for r in rows if r["recall_at_5"] is not None]
    return {
        "report_version": "1",
        "dataset_version": dataset["version"],
        "prompt_version": PROMPT_VERSION,
        "index_sha256": digest(index_path.read_bytes()),
        "top_k": 5,
        "metrics": {
            "mean_recall_at_5": sum(recalls) / len(recalls) if recalls else None,
            "retrieval_cases": len(recalls),
            "abstention_cases": sum(c["expect_abstention"] for c in dataset["cases"]),
            "requests_used": requests_used,
        },
        "limitations": (
            "Offline mode evaluates retrieval only. Phrase checks are diagnostics; humans assess correctness."
        ),
        "cases": rows,
    }


def main(argv: list[str] | None = None) -> int:
    """Offline by default; live mode requires explicit provider, model, key and request cap."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--provider", choices=("anthropic", "groq", "gemini"))
    parser.add_argument("--model")
    parser.add_argument("--max-requests", type=int)
    parser.add_argument("--max-prompt-chars", type=int, default=16000)
    args = parser.parse_args(argv)
    if not 1 <= args.max_prompt_chars <= 32000:
        parser.error("--max-prompt-chars must be between 1 and 32000")
    if args.live and (not args.provider or not args.model or not args.max_requests or not 1 <= args.max_requests <= 30):
        parser.error("--live requires --provider, --model and --max-requests between 1 and 30")
    if not args.live and any(v is not None for v in (args.provider, args.model, args.max_requests)):
        parser.error("provider/model/request options require --live")
    key = os.environ.get("OPENSHIELD_EVAL_API_KEY", "") if args.live else ""
    if args.live and not key.strip():
        parser.error("Set OPENSHIELD_EVAL_API_KEY for live mode")
    dataset = load_dataset(args.dataset)
    completion = None
    if args.live:
        from api.services.ai_provider import get_completion

        def completion(prompt: str) -> str:
            return get_completion(args.provider, key, prompt, model=args.model)

    with tempfile.TemporaryDirectory(prefix="openshield-eval-") as directory:
        index = Path(directory) / "bm25_index.json"
        build_vectorstore(index_path=index)
        report = evaluate(dataset, index, completion, args.max_requests or 0, args.max_prompt_chars)
    report.update(dataset_sha256=digest(args.dataset.read_bytes()), mode="live" if args.live else "offline")
    if args.live:
        report.update(
            provider=args.provider,
            model=args.model,
            token_usage=None,
            cost=None,
            usage_note="Existing provider abstraction returns text only; usage and cost are unavailable.",
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report["metrics"], sort_keys=True))
    return 1 if any(c["answer_status"] == "provider_error" for c in report["cases"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
