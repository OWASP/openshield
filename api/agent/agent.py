"""ReAct agent loop for the CSPM AI assistant.

Takes a natural-language question, iteratively calls CSPM tool functions,
and returns a grounded answer.  No Flask imports; this module must be
importable outside a request context.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from api.agent import tools as _tools
from api.services.ai_guard import clean_text, _QUESTION_MAX
from api.services.ai_provider import get_completion

logger = logging.getLogger(__name__)

_ANSWER_MAX = 4000
_TOOL_RESULT_MAX = 4096

_SYSTEM_PROMPT = """You are a CSPM (Cloud Security Posture Management) security assistant for Azure.

RULES:
- Answer ONLY from evidence returned by the tools below.
  Never invent findings, scores, compliance percentages, or resource names.
- If the tools return no relevant data, say so honestly.

AVAILABLE TOOLS:
1. scan_subscription(subscription_id: str) -> {"scan_id": str, "status": str}
   Queue a new scan for the subscription.

2. get_findings(subscription_id: str, severity: str|null, state: str|null) -> list
   Return findings filtered by optional severity (CRITICAL/HIGH/MEDIUM/LOW) and state.

3. get_compliance_posture(framework: str, subscription_id: str) -> dict
   Return compliance posture for a framework. Valid frameworks: "mcsb", "cis", "iso27001".

4. get_attack_paths(scan_id: str) -> list
   Return attack paths for a completed scan (stub, returns []).

5. explain_finding(finding_id: int) -> dict|null
   Return full detail for a finding including description and remediation.

6. suggest_remediation(finding_id: int) -> dict|null
   Return step-by-step remediation for a finding.

RESPONSE FORMAT:
Respond with ONLY a JSON object. Two forms are allowed:

To call a tool:
{"tool": "<tool_name>", "args": {<argument key-value pairs>}}

To give a final answer when you have enough evidence (or no tool can help further):
{"answer": "<your answer>", "confidence": "HIGH"|"LOW"}

Use "HIGH" confidence only when the tools returned concrete evidence for your answer.
Use "LOW" confidence when the evidence is sparse or a tool returned nothing.
Do not include any text outside the JSON object.
"""


def _build_prompt(messages: list[str]) -> str:
    """Concatenate all messages into a single prompt string."""
    return "\n\n".join(messages)


def _dispatch_tool(
    tool_name: str,
    args: dict,
    db_conn: Any,
    subscription_id: str,
    tenant_id: str,
    user_role: str = "viewer",
) -> Any:
    """Call the named tool. Returns the tool result or an error dict.

    Tenant isolation: subscription_id and tenant_id always come from the
    caller, never from the LLM-supplied args.
    """
    try:
        if tool_name == "scan_subscription":
            if user_role not in {"operator", "admin"}:
                return {"error": "insufficient_permissions"}
            return _tools.scan_subscription(db_conn, subscription_id, tenant_id)

        if tool_name == "get_findings":
            severity = args.get("severity")
            state = args.get("state")
            return _tools.get_findings(db_conn, subscription_id, tenant_id, severity=severity, state=state)

        if tool_name == "get_compliance_posture":
            framework = args.get("framework", "mcsb")
            return _tools.get_compliance_posture(db_conn, framework, subscription_id, tenant_id)

        if tool_name == "get_attack_paths":
            scan_id = str(args.get("scan_id", ""))
            return _tools.get_attack_paths(db_conn, scan_id, tenant_id)

        if tool_name == "explain_finding":
            finding_id = args.get("finding_id")
            return _tools.explain_finding(db_conn, finding_id, tenant_id)

        if tool_name == "suggest_remediation":
            finding_id = args.get("finding_id")
            return _tools.suggest_remediation(db_conn, finding_id, tenant_id)

        return {"error": "unknown tool"}

    except Exception as exc:  # noqa: BLE001
        logger.warning("Tool %r raised an exception: %s", tool_name, exc)
        return {"error": str(exc)}


def run_agent(
    question: str,
    subscription_id: str,
    tenant_id: str,
    db_conn: Any,
    provider: str,
    api_key: str,
    model: str = None,
    max_iterations: int = 8,
    user_role: str = "viewer",
) -> dict:
    """Run the ReAct agent loop and return a grounded answer.

    Returns:
        {
            "answer": str,
            "tools_used": list[str],
            "iterations": int,
            "confidence": "HIGH" | "LOW",
        }

    Raises:
        ValueError: if question is empty after cleaning
    """
    cleaned_question = clean_text(question, _QUESTION_MAX)
    if not cleaned_question:
        raise ValueError("question is required")

    system_message = _SYSTEM_PROMPT.strip()
    user_message = f"User question: {cleaned_question}"

    messages: list[str] = [system_message, user_message]
    tools_used: list[str] = []
    seen_calls: set[tuple] = set()

    for i in range(max_iterations):
        logger.debug("Agent iteration %d/%d", i + 1, max_iterations)

        raw = get_completion(provider, api_key, _build_prompt(messages), model)

        # Attempt to parse as JSON
        try:
            parsed = json.loads(raw.strip())
        except (json.JSONDecodeError, AttributeError):
            logger.debug("Iteration %d: unparseable LLM response, treating as final answer", i + 1)
            return {
                "answer": (raw or "")[:2000],
                "tools_used": tools_used,
                "iterations": i + 1,
                "confidence": "LOW",
            }

        if "answer" in parsed:
            logger.debug("Iteration %d: received final answer", i + 1)
            raw_answer = parsed["answer"]
            if not isinstance(raw_answer, str):
                raw_answer = (raw or "")[:_ANSWER_MAX]
            return {
                "answer": clean_text(raw_answer, _ANSWER_MAX),
                "tools_used": tools_used,
                "iterations": i + 1,
                "confidence": parsed.get("confidence", "LOW"),
            }

        if "tool" in parsed:
            tool_name = parsed["tool"]
            tool_args = parsed.get("args", {})
            logger.debug("Iteration %d: calling tool %r with args %r", i + 1, tool_name, tool_args)

            call_key = (tool_name, tuple(sorted((tool_args or {}).items())))
            if call_key in seen_calls:
                logger.debug("Iteration %d: duplicate tool call %r, skipping", i + 1, tool_name)
                messages.append(f"Tool result: {json.dumps({'note': 'duplicate call skipped'})}")
                continue
            seen_calls.add(call_key)

            result = _dispatch_tool(tool_name, tool_args, db_conn, subscription_id, tenant_id, user_role)
            tools_used.append(tool_name)
            serialized = json.dumps(result)
            if len(serialized) > _TOOL_RESULT_MAX:
                serialized = serialized[:_TOOL_RESULT_MAX] + '..."}'
            messages.append(f"Tool result: {serialized}")
            continue

        # Parsed JSON but neither "answer" nor "tool" key present
        logger.debug("Iteration %d: parsed JSON has no recognised key, treating as final answer", i + 1)
        return {
            "answer": raw[:2000],
            "tools_used": tools_used,
            "iterations": i + 1,
            "confidence": "LOW",
        }

    # Exhausted max iterations without a final answer
    logger.warning("Agent hit max_iterations=%d without a final answer", max_iterations)
    return {
        "answer": "I was unable to gather enough evidence to answer confidently.",
        "tools_used": tools_used,
        "iterations": max_iterations,
        "confidence": "LOW",
    }
