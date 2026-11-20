"""AI provider abstraction layer.

Two call styles are supported:

- ``get_completion`` — a single prompt in, a single string out. Backends:
  Anthropic, Groq, Gemini. Used by the legacy non-tool AI routes.
- ``get_tool_completion`` — native tool-use (function calling), used by the
  CSPM agent loop. Backends: Azure OpenAI (default, in-tenant), OpenAI and
  Anthropic (bring-your-own key). Returns a normalized dict that is exactly
  one of ``{"type": "text", ...}`` or ``{"type": "tool_use", ...}``.
"""

import json
import logging

import requests

from api.observability import LLM_PROVIDER_LATENCY_SECONDS

logger = logging.getLogger(__name__)

PROVIDERS = ("anthropic", "groq", "gemini")

# Providers that expose native tool-use. Azure OpenAI is the in-tenant default;
# openai and anthropic let an operator bring their own GPT / Claude key.
TOOL_PROVIDERS = ("azure_openai", "openai", "anthropic")

DEFAULT_MODELS = {
    "anthropic": "claude-3-5-haiku-20241022",
    "groq": "llama-3.1-8b-instant",
    "gemini": "gemini-1.5-flash",
    "openai": "gpt-4o-mini",
}


def get_completion(provider: str, api_key: str, prompt: str, model: str = None) -> str:
    provider = provider.lower().strip()
    if provider not in PROVIDERS:
        raise ValueError(f"Unsupported provider '{provider}'. Choose from: {', '.join(PROVIDERS)}")
    if not api_key or not api_key.strip():
        raise ValueError("api_key is required and cannot be empty")

    resolved_model = model or DEFAULT_MODELS[provider]

    with LLM_PROVIDER_LATENCY_SECONDS.labels(provider=provider).time():
        if provider == "anthropic":
            return _anthropic(api_key, prompt, resolved_model)
        if provider == "groq":
            return _groq(api_key, prompt, resolved_model)
        return _gemini(api_key, prompt, resolved_model)


def _anthropic(api_key: str, prompt: str, model: str) -> str:
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=30,
        )
        if resp.status_code == 401:
            raise ValueError("Invalid Anthropic API key")
        if resp.status_code == 429:
            raise RuntimeError("Anthropic rate limit reached, try again later")
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]
    except (ValueError, RuntimeError):
        raise
    except requests.exceptions.RequestException as exc:
        logger.error("Anthropic request failed: %s", exc)
        raise RuntimeError(f"Anthropic request failed: {exc}") from exc


def _groq(api_key: str, prompt: str, model: str) -> str:
    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1024,
            },
            timeout=30,
        )
        if resp.status_code == 401:
            raise ValueError("Invalid Groq API key")
        if resp.status_code == 429:
            raise RuntimeError("Groq rate limit reached, try again later")
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
    except (ValueError, RuntimeError):
        raise
    except requests.exceptions.RequestException as exc:
        logger.error("Groq request failed: %s", exc)
        raise RuntimeError(f"Groq request failed: {exc}") from exc


def _gemini(api_key: str, prompt: str, model: str) -> str:
    try:
        resp = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            headers={"x-goog-api-key": api_key, "content-type": "application/json"},
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=30,
        )
        if resp.status_code == 400 and "API_KEY_INVALID" in resp.text:
            raise ValueError("Invalid Gemini API key")
        if resp.status_code == 429:
            raise RuntimeError("Gemini rate limit reached, try again later")
        resp.raise_for_status()
        return resp.json()["candidates"][0]["content"]["parts"][0]["text"]
    except (ValueError, RuntimeError):
        raise
    except requests.exceptions.RequestException as exc:
        logger.error("Gemini request failed: %s", exc)
        raise RuntimeError(f"Gemini request failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Native tool-use (function calling) for the CSPM agent loop
# ---------------------------------------------------------------------------


def get_tool_completion(
    provider: str,
    api_key: str,
    system: str,
    messages: list,
    tools: list,
    model: str = None,
    *,
    azure_endpoint: str = None,
    azure_deployment: str = None,
    api_version: str = "2024-10-21",
) -> dict:
    """Run one native tool-use turn and return a normalized result.

    Returns exactly one of:
        {"type": "text", "text": str}
        {"type": "tool_use", "id": str, "name": str, "args": dict}

    ``messages`` is a list of {"role": "user"|"assistant"|"tool", "content": str}.
    ``tools`` is a list of OpenAI-style function specs
    {"type": "function", "function": {"name", "description", "parameters"}}.
    """
    provider = provider.lower().strip()
    if provider not in TOOL_PROVIDERS:
        raise ValueError(f"Unsupported tool-use provider '{provider}'. Choose from: {', '.join(TOOL_PROVIDERS)}")
    # azure_openai supports Managed Identity (empty api_key); all other providers require a key.
    if provider != "azure_openai" and (not api_key or not api_key.strip()):
        raise ValueError("api_key is required and cannot be empty")

    with LLM_PROVIDER_LATENCY_SECONDS.labels(provider=provider).time():
        if provider == "azure_openai":
            return _azure_openai_tools(api_key, system, messages, tools, azure_endpoint, azure_deployment, api_version)
        if provider == "openai":
            return _openai_tools(api_key, system, messages, tools, model or DEFAULT_MODELS["openai"])
        return _anthropic_tools(api_key, system, messages, tools, model or DEFAULT_MODELS["anthropic"])


def _normalize_openai_message(message: dict) -> dict:
    """Normalize an OpenAI/Azure chat-completions message into our shape."""
    tool_calls = message.get("tool_calls") or []
    if tool_calls:
        call = tool_calls[0]
        fn = call.get("function", {})
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except (ValueError, TypeError):
            args = {}
        if not isinstance(args, dict):
            args = {}
        return {"type": "tool_use", "id": call.get("id", ""), "name": fn.get("name", ""), "args": args}
    return {"type": "text", "text": message.get("content") or ""}


def _openai_style_payload(system: str, messages: list, tools: list) -> dict:
    payload = {"messages": [{"role": "system", "content": system}, *messages], "max_tokens": 1024}
    if tools:
        payload["tools"] = tools
    return payload


def _azure_openai_tools(api_key, system, messages, tools, endpoint, deployment, api_version):
    if not endpoint or not deployment:
        raise ValueError("azure_openai requires azure_endpoint and azure_deployment")
    url = f"{endpoint.rstrip('/')}/openai/deployments/{deployment}/chat/completions?api-version={api_version}"
    if api_key and api_key.strip():
        auth_headers = {"api-key": api_key}
    else:
        # No API key: use Managed Identity via DefaultAzureCredential.
        from azure.identity import DefaultAzureCredential  # noqa: PLC0415
        token = DefaultAzureCredential().get_token("https://cognitiveservices.azure.com/.default").token
        auth_headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.post(
            url,
            headers={**auth_headers, "content-type": "application/json"},
            json=_openai_style_payload(system, messages, tools),
            timeout=30,
        )
        if resp.status_code == 401:
            raise ValueError("Invalid Azure OpenAI api-key")
        if resp.status_code == 429:
            raise RuntimeError("Azure OpenAI rate limit reached, try again later")
        resp.raise_for_status()
        return _normalize_openai_message(resp.json()["choices"][0]["message"])
    except (ValueError, RuntimeError):
        raise
    except requests.exceptions.RequestException as exc:
        logger.error("Azure OpenAI request failed: %s", exc)
        raise RuntimeError(f"Azure OpenAI request failed: {exc}") from exc


def _openai_tools(api_key, system, messages, tools, model):
    payload = _openai_style_payload(system, messages, tools)
    payload["model"] = model
    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "content-type": "application/json"},
            json=payload,
            timeout=30,
        )
        if resp.status_code == 401:
            raise ValueError("Invalid OpenAI API key")
        if resp.status_code == 429:
            raise RuntimeError("OpenAI rate limit reached, try again later")
        resp.raise_for_status()
        return _normalize_openai_message(resp.json()["choices"][0]["message"])
    except (ValueError, RuntimeError):
        raise
    except requests.exceptions.RequestException as exc:
        logger.error("OpenAI request failed: %s", exc)
        raise RuntimeError(f"OpenAI request failed: {exc}") from exc


def _anthropic_tools(api_key, system, messages, tools, model):
    anthropic_tools = [
        {
            "name": t["function"]["name"],
            "description": t["function"].get("description", ""),
            "input_schema": t["function"].get("parameters", {}) or {"type": "object", "properties": {}},
        }
        for t in tools
    ]
    body = {
        "model": model,
        "max_tokens": 1024,
        "system": system,
        "messages": [{"role": m["role"], "content": m["content"]} for m in messages],
    }
    if anthropic_tools:
        body["tools"] = anthropic_tools
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json=body,
            timeout=30,
        )
        if resp.status_code == 401:
            raise ValueError("Invalid Anthropic API key")
        if resp.status_code == 429:
            raise RuntimeError("Anthropic rate limit reached, try again later")
        resp.raise_for_status()
        blocks = resp.json().get("content", [])
        for block in blocks:
            if block.get("type") == "tool_use":
                args = block.get("input", {})
                return {
                    "type": "tool_use",
                    "id": block.get("id", ""),
                    "name": block.get("name", ""),
                    "args": args if isinstance(args, dict) else {},
                }
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        return {"type": "text", "text": text}
    except (ValueError, RuntimeError):
        raise
    except requests.exceptions.RequestException as exc:
        logger.error("Anthropic request failed: %s", exc)
        raise RuntimeError(f"Anthropic request failed: {exc}") from exc
