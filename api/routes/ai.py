"""AI insights routes: executive summary, RAG-grounded analysis, and Q&A."""

import json
import logging

from flask import Blueprint, jsonify, request

from api.rate_limit import rate_limit
from api.services.ai_provider import PROVIDERS as SUPPORTED_PROVIDERS
from api.services.ai_provider import get_completion
from api.validation import (
    MAX_API_KEY_LENGTH,
    MAX_MODEL_LENGTH,
    MAX_QUESTION_LENGTH,
    MODEL_RE,
    VALIDATION_ERROR_MESSAGE,
    ValidationError,
    bounded_string,
    choice,
    findings_list,
    reject_unknown_fields,
    require_json_object,
)
from ai.retriever import retrieve, VectorStoreNotBuilt
from openshield.severity import severity_rank as contract_severity_rank

ai_bp = Blueprint("ai", __name__)
logger = logging.getLogger(__name__)

_AI_RATE_LIMIT = 20  # requests per minute per client IP, per endpoint


def severity_rank(finding: dict) -> int:
    value = finding.get("severity")
    return contract_severity_rank(value) if value not in (None, "") else -1


def _build_summary_prompt(findings: list) -> str:
    lines = []
    for f in findings:
        title = f.get("title") or f.get("rule_name") or "Untitled"
        lines.append(f"- [{f.get('severity', 'UNKNOWN')}] {title}: {f.get('description', 'No description provided.')}")
    findings_text = "\n".join(lines)
    return (
        "You are a security advisor writing for a non-technical executive audience.\n"
        "Based on the following cloud security findings, write a concise executive summary.\n"
        "Avoid technical jargon. Mention the overall security risk level and likely business or operational impact.\n"
        "Do not invent findings. If information is missing, say so clearly.\n\n"
        f"Findings:\n{findings_text}\n\n"
        "Executive Summary:"
    )


def _build_question_prompt(sorted_findings: list, question: str) -> str:
    lines = []
    for f in sorted_findings:
        rule_id = f.get("rule_id", "")
        title = f.get("title") or f.get("rule_name") or "Untitled"
        severity = f.get("severity", "UNKNOWN")
        description = f.get("description", "No description provided.")
        remediation = f.get("remediation", "No remediation detail provided.")
        label = f"{rule_id} — {title}" if rule_id else title
        lines.append(f"- [{severity}] {label}: {description} Remediation: {remediation}")
    findings_text = "\n".join(lines)
    return (
        "You are a cloud security assistant.\n"
        "Answer the user's question using only the scan findings provided below.\n"
        "Do not invent facts or assume scan results that are not listed.\n"
        "Prioritise high severity, exploitable, and compliance-impacting findings, "
        "and consider remediation urgency.\n"
        "Be concise but useful. If the findings are insufficient to answer "
        "confidently, say what evidence is missing.\n\n"
        f"Question: {question}\n\n"
        f"Findings (severity order):\n{findings_text}\n\n"
        "Answer:"
    )


def _build_remediation_prompt(sorted_findings: list) -> str:
    lines = []
    for f in sorted_findings:
        rule_id = f.get("rule_id", "")
        title = f.get("title") or f.get("rule_name") or "Untitled"
        severity = f.get("severity", "UNKNOWN")
        remediation = f.get("remediation", "No remediation detail provided.")
        label = f"{rule_id} — {title}" if rule_id else title
        lines.append(f"- [{severity}] {label}: {remediation}")
    findings_text = "\n".join(lines)
    return (
        "You are a cloud security engineer writing a remediation plan.\n"
        "The findings below are already sorted by severity (Critical first, then High, Medium, Low, Informational).\n"
        "For each finding, provide practical, actionable fix steps.\n"
        "Reference the rule ID and title where available.\n"
        "Do not invent findings. If a finding lacks remediation detail, state what information is missing.\n\n"
        f"Findings (severity order):\n{findings_text}\n\n"
        "Prioritised Remediation Plan:"
    )


def _build_threat_simulation_prompt(findings_text: str, context: str) -> str:
    return (
        "You are a red team security analyst. Using the Azure cloud security "
        "findings below and the grounded knowledge provided, construct a realistic "
        "attacker kill chain narrative showing how a real attacker would exploit "
        "these misconfigurations in sequence.\n\n"
        "Respond with valid JSON only, no markdown. Use this exact structure:\n"
        "{\n"
        '  "summary": "<one sentence overall attack narrative>",\n'
        '  "overall_risk": "<CRITICAL|HIGH|MEDIUM|LOW>",\n'
        '  "stages": [\n'
        "    {\n"
        '      "stage": "<initial_access|reconnaissance|lateral_movement|privilege_escalation|persistence|impact>",\n'
        '      "title": "<short stage title>",\n'
        '      "description": "<what the attacker does and why this finding enables it>",\n'
        '      "findings_used": ["<rule_id>"],\n'
        '      "technique": "<MITRE ATT&CK technique name if applicable>"\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        "Rules:\n"
        "- Only include stages directly enabled by the findings provided.\n"
        "- Map each stage to at least one rule_id from the findings list.\n"
        "- Do not invent findings or capabilities not present in the data.\n"
        "- If findings are insufficient for a full kill chain, only include supported stages.\n\n"
        f"GROUNDED KNOWLEDGE:\n{context}\n\n"
        f"FINDINGS:\n{findings_text}"
    )


def _findings_to_text(findings):
    ordered = sorted(
        findings,
        key=severity_rank,
        reverse=True,
    )
    lines = []
    for i, f in enumerate(ordered, 1):
        lines.append(
            f"{i}. [{f.get('severity', 'UNKNOWN')}] "
            f"{f.get('rule_name', 'Unknown')} on "
            f"{f.get('resource_name', 'unknown resource')}: "
            f"{f.get('description', '')}"
        )
    return "\n".join(lines) if lines else "No findings."


def _context_for(query):
    chunks = retrieve(query, n_results=5)
    context = "\n".join(f"- ({c['source']}) {c['text']}" for c in chunks)
    # Extract structured source_meta for the frontend badges
    sources = [c["source_meta"] for c in chunks if c["source_meta"]]
    return context, sources


def _read_request():
    try:
        body = require_json_object(request.get_json(silent=True))
        reject_unknown_fields(body, {"provider", "api_key", "model", "findings", "question"})
        body["provider"] = choice(body.get("provider"), "provider", SUPPORTED_PROVIDERS, case="lower")
        body["api_key"] = bounded_string(body.get("api_key"), "api_key", maximum=MAX_API_KEY_LENGTH)
        if body.get("model") is not None:
            body["model"] = bounded_string(body["model"], "model", maximum=MAX_MODEL_LENGTH, pattern=MODEL_RE)
            if ".." in body["model"]:
                raise ValidationError("model has an invalid format")
        return body, None
    except ValidationError:
        return None, (jsonify({"error": VALIDATION_ERROR_MESSAGE}), 400)


_AI_ERROR_MESSAGES = {
    503: "AI knowledge base is not available",
    400: "Invalid AI request parameters",
    502: "AI provider request failed",
}


def _ai_error_response(exc: Exception, status: int, log_context: str):
    """Return a safe, generic error response, logging the real exception server-side.

    Never reflect str(exc) back to the client: get_completion() wraps
    third-party provider errors (e.g. "Anthropic request failed: {exc}"),
    which could carry response bodies or connection details from the
    underlying HTTP client that shouldn't reach the caller.
    """
    logger.error("%s: %s", log_context, exc)
    return jsonify({"error": _AI_ERROR_MESSAGES.get(status, "AI request failed")}), status


@ai_bp.post("/api/ai/insights")
@rate_limit(_AI_RATE_LIMIT)
def insights():
    data, error = _read_request()
    if error:
        return error
    try:
        provider = data["provider"]
        api_key = data["api_key"]
        findings = findings_list(data.get("findings"), required=True)
        question = ""
        if data.get("question") is not None:
            if not isinstance(data["question"], str):
                raise ValidationError("question must be a string")
            if data["question"].strip():
                question = bounded_string(data["question"], "question", maximum=MAX_QUESTION_LENGTH)
    except ValidationError:
        return jsonify({"error": VALIDATION_ERROR_MESSAGE}), 400

    sorted_findings = sorted(findings, key=severity_rank, reverse=True)

    summary_prompt = _build_summary_prompt(sorted_findings)
    remediation_prompt = _build_remediation_prompt(sorted_findings)

    try:
        executive_summary = get_completion(provider, api_key, summary_prompt)
        remediation_plan = get_completion(provider, api_key, remediation_prompt)
        answer = None
        if question:
            question_prompt = _build_question_prompt(sorted_findings, question)
            answer = get_completion(provider, api_key, question_prompt)
    except Exception:
        logger.warning("AI provider request failed for provider=%s", provider)
        return jsonify({"error": "AI provider request failed"}), 502

    response = {
        "executive_summary": executive_summary,
        "remediation_plan": remediation_plan,
    }
    if question:
        response["answer"] = answer

    return jsonify(response)


@ai_bp.post("/api/ai/summary")
@rate_limit(_AI_RATE_LIMIT)
def ai_summary():
    body, error = _read_request()
    if error:
        return error
    try:
        findings = findings_list(body.get("findings"))
    except ValidationError:
        return jsonify({"error": VALIDATION_ERROR_MESSAGE}), 400

    findings_text = _findings_to_text(findings)
    try:
        context, sources = _context_for(findings_text)
    except VectorStoreNotBuilt as exc:
        return _ai_error_response(exc, 503, "Vector store unavailable in ai_summary")

    prompt = (
        "You are a cloud security advisor. Using ONLY the grounded knowledge "
        "below, write a plain English executive summary of the security "
        "posture for a non technical reader. Keep it under 120 words.\n\n"
        f"GROUNDED KNOWLEDGE:\n{context}\n\nFINDINGS:\n{findings_text}"
    )
    try:
        answer = get_completion(body["provider"], body["api_key"], prompt, model=body.get("model"))
    except ValueError as exc:
        return _ai_error_response(exc, 400, "Invalid request in ai_summary")
    except RuntimeError as exc:
        return _ai_error_response(exc, 502, "Provider failure in ai_summary")

    return jsonify(
        {
            "summary": answer,
            "sources": sources,
            "provider": body["provider"],
            "model": body.get("model"),
        }
    )


@ai_bp.post("/api/ai/prioritise")
@rate_limit(_AI_RATE_LIMIT)
def ai_prioritise():
    body, error = _read_request()
    if error:
        return error
    try:
        findings = findings_list(body.get("findings"))
    except ValidationError:
        return jsonify({"error": VALIDATION_ERROR_MESSAGE}), 400

    findings_text = _findings_to_text(findings)
    try:
        context, sources = _context_for(findings_text)
    except VectorStoreNotBuilt as exc:
        return _ai_error_response(exc, 503, "Vector store unavailable in ai_prioritise")

    prompt = (
        "You are a cloud security advisor. Using ONLY the grounded knowledge "
        "below, rank these findings by real world exploitability and business "
        "risk, not just the severity label. Respond with valid JSON only, no "
        "markdown, as a list of objects with fields: priority, rule_name, "
        "resource_name, severity, reason.\n\n"
        f"GROUNDED KNOWLEDGE:\n{context}\n\nFINDINGS:\n{findings_text}"
    )
    try:
        raw = get_completion(body["provider"], body["api_key"], prompt, model=body.get("model"))
    except ValueError as exc:
        return _ai_error_response(exc, 400, "Invalid request in ai_prioritise")
    except RuntimeError as exc:
        return _ai_error_response(exc, 502, "Provider failure in ai_prioritise")

    try:
        prioritised = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        prioritised = raw

    return jsonify(
        {
            "prioritised_findings": prioritised,
            "sources": sources,
            "provider": body["provider"],
            "model": body.get("model"),
        }
    )


@ai_bp.post("/api/ai/ask")
@rate_limit(_AI_RATE_LIMIT)
def ai_ask():
    body, error = _read_request()
    if error:
        return error
    try:
        question = bounded_string(body.get("question"), "question", maximum=MAX_QUESTION_LENGTH)
        findings = findings_list(body.get("findings"))
    except ValidationError:
        return jsonify({"error": VALIDATION_ERROR_MESSAGE}), 400

    try:
        context, sources = _context_for(question)
    except VectorStoreNotBuilt as exc:
        return _ai_error_response(exc, 503, "Vector store unavailable in ai_ask")

    findings_text = _findings_to_text(findings) if findings else "Not provided."

    prompt = (
        "You are a cloud security advisor. Answer the question using ONLY the "
        "grounded knowledge below. If the answer is not in the knowledge, say "
        "so honestly. Reference specific rule IDs or controls where relevant."
        f"\n\nGROUNDED KNOWLEDGE:\n{context}\n\n"
        f"CURRENT FINDINGS:\n{findings_text}\n\nQUESTION: {question}"
    )
    try:
        answer = get_completion(body["provider"], body["api_key"], prompt, model=body.get("model"))
    except ValueError as exc:
        return _ai_error_response(exc, 400, "Invalid request in ai_ask")
    except RuntimeError as exc:
        return _ai_error_response(exc, 502, "Provider failure in ai_ask")

    return jsonify(
        {
            "answer": answer,
            "sources": sources,
            "provider": body["provider"],
            "model": body.get("model"),
        }
    )


@ai_bp.post("/api/ai/threat-simulation")
@rate_limit(_AI_RATE_LIMIT)
def ai_threat_simulation():
    body, error = _read_request()
    if error:
        return error
    try:
        findings = findings_list(body.get("findings"), required=True)
    except ValidationError:
        return jsonify({"error": VALIDATION_ERROR_MESSAGE}), 400

    findings_text = _findings_to_text(findings)
    try:
        context, sources = _context_for(findings_text)
    except VectorStoreNotBuilt as exc:
        return _ai_error_response(exc, 503, "Vector store unavailable in ai_threat_simulation")

    prompt = _build_threat_simulation_prompt(findings_text, context)
    try:
        raw = get_completion(body["provider"], body["api_key"], prompt, model=body.get("model"))
    except ValueError as exc:
        return _ai_error_response(exc, 400, "Invalid request in ai_threat_simulation")
    except RuntimeError as exc:
        return _ai_error_response(exc, 502, "Provider failure in ai_threat_simulation")

    try:
        simulation = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        simulation = raw

    return jsonify(
        {
            "threat_simulation": simulation,
            "sources": sources,
            "provider": body["provider"],
            "model": body.get("model"),
        }
    )
