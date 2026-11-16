"""Unit tests for api.agent.agent - the native tool-use loop.

The provider is faked via monkeypatch; no live network calls are made. The
fake returns scripted get_tool_completion outputs in order and records the
messages it was handed so we can assert on untrusted-data wrapping.
"""

import json

import pytest

from api.agent import agent as agent_mod


_SUB_ID = "sub-123"
_TENANT_ID = "tenant-abc"


class _FakeProvider:
    """Returns scripted get_tool_completion outputs in order, recording calls."""

    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.seen_messages = []

    def __call__(self, provider, api_key, system, messages, tools, model=None, **kwargs):
        # Deep-copy the messages snapshot so later mutation does not change it.
        self.seen_messages.append(json.loads(json.dumps(messages)))
        if not self.outputs:
            return {"type": "text", "text": "done"}
        return self.outputs.pop(0)


class _FakeConn:
    """Tools are monkeypatched, so the connection is never touched."""


def _run(monkeypatch, outputs, **overrides):
    fake = _FakeProvider(outputs)
    monkeypatch.setattr(agent_mod.ai_provider, "get_tool_completion", fake)
    kwargs = dict(
        question="any question",
        subscription_id=_SUB_ID,
        tenant_id=_TENANT_ID,
        db_conn=_FakeConn(),
        provider="azure_openai",
        api_key="k",
        azure_endpoint="https://x.openai.azure.com",
        azure_deployment="gpt4o",
    )
    kwargs.update(overrides)
    result = agent_mod.run_agent(**kwargs)
    return result, fake


def test_text_answer_without_tools_is_low_confidence(monkeypatch):
    result, _ = _run(monkeypatch, [{"type": "text", "text": "Everything looks fine."}])
    assert result["answer"] == "Everything looks fine."
    assert result["tools_used"] == []
    assert result["iterations"] == 1
    assert result["confidence"] == "LOW"  # no tool grounded the answer


def test_tool_then_answer_is_grounded_high(monkeypatch):
    monkeypatch.setattr(
        agent_mod._tools, "get_findings", lambda *a, **k: [{"finding_id": 1, "severity": "HIGH"}]
    )
    result, _ = _run(
        monkeypatch,
        [
            {"type": "tool_use", "id": "1", "name": "get_findings", "args": {"severity": "HIGH"}},
            {"type": "text", "text": "You have 1 HIGH finding."},
        ],
    )
    assert result["tools_used"] == ["get_findings"]
    assert "HIGH finding" in result["answer"]
    assert result["iterations"] == 2
    assert result["confidence"] == "HIGH"


def test_empty_findings_still_counts_as_grounded(monkeypatch):
    monkeypatch.setattr(agent_mod._tools, "get_findings", lambda *a, **k: [])
    result, _ = _run(
        monkeypatch,
        [
            {"type": "tool_use", "id": "1", "name": "get_findings", "args": {}},
            {"type": "text", "text": "You have no findings."},
        ],
    )
    assert result["confidence"] == "HIGH"


def test_tool_error_result_keeps_confidence_low(monkeypatch):
    monkeypatch.setattr(agent_mod._tools, "get_findings", lambda *a, **k: [{"error": "db_error"}])
    result, _ = _run(
        monkeypatch,
        [
            {"type": "tool_use", "id": "1", "name": "get_findings", "args": {}},
            {"type": "text", "text": "I could not read findings."},
        ],
    )
    assert result["confidence"] == "LOW"


def test_write_tool_denied_for_viewer(monkeypatch):
    called = {"scan": False}

    def _scan(*a, **k):
        called["scan"] = True
        return {"scan_id": "x", "status": "pending"}

    monkeypatch.setattr(agent_mod._tools, "scan_subscription", _scan)
    result, fake = _run(
        monkeypatch,
        [
            {"type": "tool_use", "id": "1", "name": "scan_subscription", "args": {}},
            {"type": "text", "text": "I cannot start a scan with your role."},
        ],
        user_role="viewer",
    )
    assert called["scan"] is False  # guardrail blocked the call entirely
    # The denial is surfaced to the model as untrusted data, not silently dropped.
    last_user_msg = fake.seen_messages[-1][-1]["content"]
    assert "insufficient_permissions" in last_user_msg


def test_write_tool_allowed_for_operator(monkeypatch):
    called = {"scan": False}

    def _scan(*a, **k):
        called["scan"] = True
        return {"scan_id": "x", "status": "pending", "created": True}

    monkeypatch.setattr(agent_mod._tools, "scan_subscription", _scan)
    _run(
        monkeypatch,
        [
            {"type": "tool_use", "id": "1", "name": "scan_subscription", "args": {}},
            {"type": "text", "text": "Scan queued."},
        ],
        user_role="operator",
    )
    assert called["scan"] is True


def test_tool_results_are_wrapped_as_untrusted(monkeypatch):
    monkeypatch.setattr(
        agent_mod._tools, "get_findings", lambda *a, **k: [{"finding_id": 1}]
    )
    _, fake = _run(
        monkeypatch,
        [
            {"type": "tool_use", "id": "1", "name": "get_findings", "args": {}},
            {"type": "text", "text": "done"},
        ],
    )
    # The second provider call must have seen the tool result wrapped.
    second_call_messages = fake.seen_messages[1]
    wrapped = second_call_messages[-1]["content"]
    assert "untrusted-data" in wrapped
    assert "get_findings" in wrapped


def test_duplicate_tool_call_is_not_repeated(monkeypatch):
    calls = {"n": 0}

    def _findings(*a, **k):
        calls["n"] += 1
        return []

    monkeypatch.setattr(agent_mod._tools, "get_findings", _findings)
    result, _ = _run(
        monkeypatch,
        [
            {"type": "tool_use", "id": "1", "name": "get_findings", "args": {}},
            {"type": "tool_use", "id": "2", "name": "get_findings", "args": {}},  # dup
            {"type": "text", "text": "answer"},
        ],
    )
    assert calls["n"] == 1  # second identical call skipped
    assert result["answer"] == "answer"


def test_malformed_tool_name_does_not_raise(monkeypatch):
    result, _ = _run(
        monkeypatch, [{"type": "tool_use", "id": "1", "name": 123, "args": "not a dict"}]
    )
    assert result["confidence"] == "LOW"
    assert isinstance(result["answer"], str)


def test_provider_exception_degrades_gracefully(monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("provider down")

    monkeypatch.setattr(agent_mod.ai_provider, "get_tool_completion", _boom)
    result = agent_mod.run_agent(
        question="q",
        subscription_id=_SUB_ID,
        tenant_id=_TENANT_ID,
        db_conn=_FakeConn(),
        provider="azure_openai",
        api_key="k",
        azure_endpoint="e",
        azure_deployment="d",
    )
    assert result["confidence"] == "LOW"
    assert "could not be reached" in result["answer"].lower()


def test_max_iterations_fallback(monkeypatch):
    monkeypatch.setattr(agent_mod._tools, "get_findings", lambda *a, **k: [])
    # Always ask for a differently-argued tool so dedupe never short-circuits.
    outputs = [
        {"type": "tool_use", "id": str(i), "name": "get_findings", "args": {"severity": f"S{i}"}}
        for i in range(8)
    ]
    result, _ = _run(monkeypatch, outputs, max_iterations=8)
    assert result["iterations"] == 8
    assert result["confidence"] == "LOW"
    assert "unable to gather" in result["answer"].lower()


def test_empty_question_raises():
    with pytest.raises(ValueError):
        agent_mod.run_agent(
            question="   ",
            subscription_id=_SUB_ID,
            tenant_id=_TENANT_ID,
            db_conn=_FakeConn(),
            provider="azure_openai",
            api_key="k",
            azure_endpoint="e",
            azure_deployment="d",
        )


def test_tools_used_records_order(monkeypatch):
    monkeypatch.setattr(agent_mod._tools, "get_findings", lambda *a, **k: [])
    monkeypatch.setattr(
        agent_mod._tools, "get_compliance_posture", lambda *a, **k: {"framework": "mcsb", "score": 0.9}
    )
    result, _ = _run(
        monkeypatch,
        [
            {"type": "tool_use", "id": "1", "name": "get_findings", "args": {}},
            {"type": "tool_use", "id": "2", "name": "get_compliance_posture", "args": {"framework": "mcsb"}},
            {"type": "text", "text": "both called"},
        ],
    )
    assert result["tools_used"] == ["get_findings", "get_compliance_posture"]
    assert result["iterations"] == 3
