"""Tests for the native tool-use provider adapter (get_tool_completion).

Covers the three shippable backends:
  - azure_openai  (default, in-tenant)
  - openai        (bring-your-own GPT key)
  - anthropic     (bring-your-own Claude key)

Provider calls are plain HTTP, faked here via monkeypatch (no network).
"""

import json
from urllib.parse import urlparse

from api.services import ai_provider


class _Resp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise AssertionError(f"unexpected status {self.status_code}")


def _capture_openai_style(monkeypatch, message):
    """Fake an OpenAI/Azure chat-completions response and capture the request."""
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        return _Resp(200, {"choices": [{"message": message}]})

    monkeypatch.setattr(ai_provider.requests, "post", fake_post)
    return captured


# --- Azure OpenAI -----------------------------------------------------------


def test_azure_openai_returns_normalized_text(monkeypatch):
    captured = _capture_openai_style(monkeypatch, {"role": "assistant", "content": "hello"})
    out = ai_provider.get_tool_completion(
        "azure_openai",
        "k",
        "sys",
        [{"role": "user", "content": "hi"}],
        tools=[],
        azure_endpoint="https://x.openai.azure.com",
        azure_deployment="gpt4o",
    )
    assert out == {"type": "text", "text": "hello"}
    assert urlparse(captured["url"]).netloc == "x.openai.azure.com"
    assert captured["headers"]["api-key"] == "k"


def test_azure_openai_returns_normalized_tool_call(monkeypatch):
    message = {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "call_1",
                "type": "function",
                "function": {"name": "get_findings", "arguments": '{"severity": "HIGH"}'},
            }
        ],
    }
    _capture_openai_style(monkeypatch, message)
    out = ai_provider.get_tool_completion(
        "azure_openai",
        "k",
        "sys",
        [{"role": "user", "content": "hi"}],
        tools=[{"type": "function", "function": {"name": "get_findings", "parameters": {}}}],
        azure_endpoint="https://x.openai.azure.com",
        azure_deployment="gpt4o",
    )
    assert out == {"type": "tool_use", "id": "call_1", "name": "get_findings", "args": {"severity": "HIGH"}}


def test_azure_requires_endpoint_and_deployment(monkeypatch):
    _capture_openai_style(monkeypatch, {"role": "assistant", "content": "x"})
    try:
        ai_provider.get_tool_completion(
            "azure_openai",
            "k",
            "sys",
            [{"role": "user", "content": "hi"}],
            tools=[],
        )
    except ValueError as exc:
        assert "azure_endpoint" in str(exc)
    else:
        raise AssertionError("expected ValueError when azure config is missing")


def test_tool_call_with_malformed_arguments_becomes_empty_args(monkeypatch):
    message = {
        "role": "assistant",
        "content": None,
        "tool_calls": [{"id": "c", "type": "function", "function": {"name": "get_findings", "arguments": "not json"}}],
    }
    _capture_openai_style(monkeypatch, message)
    out = ai_provider.get_tool_completion(
        "azure_openai",
        "k",
        "sys",
        [{"role": "user", "content": "hi"}],
        tools=[],
        azure_endpoint="https://x.openai.azure.com",
        azure_deployment="gpt4o",
    )
    assert out == {"type": "tool_use", "id": "c", "name": "get_findings", "args": {}}


# --- OpenAI (bring-your-own GPT key) ---------------------------------------


def test_openai_returns_normalized_text(monkeypatch):
    captured = _capture_openai_style(monkeypatch, {"role": "assistant", "content": "hi there"})
    out = ai_provider.get_tool_completion(
        "openai",
        "sk-test",
        "sys",
        [{"role": "user", "content": "hi"}],
        tools=[],
    )
    assert out == {"type": "text", "text": "hi there"}
    assert urlparse(captured["url"]).netloc == "api.openai.com"
    assert captured["headers"]["Authorization"] == "Bearer sk-test"


def test_openai_returns_normalized_tool_call(monkeypatch):
    message = {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {"id": "call_x", "type": "function", "function": {"name": "get_findings", "arguments": '{"state": "OPEN"}'}}
        ],
    }
    _capture_openai_style(monkeypatch, message)
    out = ai_provider.get_tool_completion(
        "openai",
        "sk-test",
        "sys",
        [{"role": "user", "content": "hi"}],
        tools=[{"type": "function", "function": {"name": "get_findings", "parameters": {}}}],
    )
    assert out == {"type": "tool_use", "id": "call_x", "name": "get_findings", "args": {"state": "OPEN"}}


# --- Anthropic (bring-your-own Claude key) ---------------------------------


def test_anthropic_returns_normalized_text(monkeypatch):
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        return _Resp(200, {"content": [{"type": "text", "text": "claude says hi"}]})

    monkeypatch.setattr(ai_provider.requests, "post", fake_post)
    out = ai_provider.get_tool_completion(
        "anthropic",
        "k",
        "sys",
        [{"role": "user", "content": "hi"}],
        tools=[],
    )
    assert out == {"type": "text", "text": "claude says hi"}
    assert urlparse(captured["url"]).netloc == "api.anthropic.com"
    # tools are translated into Anthropic's input_schema shape
    assert "system" in captured["json"]


def test_anthropic_returns_normalized_tool_call(monkeypatch):
    def fake_post(url, headers=None, json=None, timeout=None):
        return _Resp(
            200,
            {
                "content": [
                    {"type": "tool_use", "id": "toolu_1", "name": "get_findings", "input": {"severity": "LOW"}},
                ]
            },
        )

    monkeypatch.setattr(ai_provider.requests, "post", fake_post)
    out = ai_provider.get_tool_completion(
        "anthropic",
        "k",
        "sys",
        [{"role": "user", "content": "hi"}],
        tools=[{"type": "function", "function": {"name": "get_findings", "description": "d", "parameters": {}}}],
    )
    assert out == {"type": "tool_use", "id": "toolu_1", "name": "get_findings", "args": {"severity": "LOW"}}


# --- validation -------------------------------------------------------------


def test_unsupported_provider_raises():
    try:
        ai_provider.get_tool_completion("groq", "k", "sys", [], tools=[])
    except ValueError as exc:
        assert "groq" in str(exc)
    else:
        raise AssertionError("expected ValueError for unsupported tool-use provider")


def test_empty_api_key_raises():
    try:
        ai_provider.get_tool_completion("openai", "  ", "sys", [], tools=[])
    except ValueError as exc:
        assert "api_key" in str(exc)
    else:
        raise AssertionError("expected ValueError for empty api_key")
