"""AI insights routes: executive summary, RAG-grounded analysis, and Q&A.

Evidence and prompt safety (#357):

* Findings are loaded server-side from a completed scan (``scan_id``, or the
  latest completed scan when omitted), the same data ``/api/findings`` serves.
  A client-supplied ``findings`` array is still accepted for compatibility but
  is deprecated, and every response says which evidence it was built from.
* Untrusted text is fenced with :mod:`api.services.ai_guard` before it reaches
  a prompt, and JSON-producing endpoints validate the model's output against
  the evidence instead of passing raw completions through.
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

from flask import Blueprint, g, jsonify, request

from api.models.finding import DatabaseManager
from api.rate_limit import rate_limit
from api.services.ai_guard import (
    AIResponseInvalid,
    clean_question,
    data_block,
    finding_record,
    new_boundary,
    parse_json_response,
    untrusted_data_rules,
    validate_prioritisation,
    validate_threat_simulation,
)
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
    uuid_string,
)
from ai.retriever import retrieve, VectorStoreNotBuilt
from openshield.severity import SeverityContractError
from openshield.severity import severity_rank as contract_severity_rank

ai_bp = Blueprint("ai", __name__)
logger = logging.getLogger(__name__)

_AI_RATE_LIMIT = 20  # requests per minute per client IP, per endpoint

# Highest-severity findings placed into one prompt. A completed scan can hold
# up to 1000 findings; beyond this the context window, not the evidence, is
# the limiting factor. The response reports both counts.
_MAX_PROMPT_FINDINGS = 200


def severity_rank(finding: dict) -> int:
    value = finding.get("severity")
    try:
        return contract_severity_rank(value) if value not in (None, "") else -1
    except SeverityContractError:
        return -1


# --------------------------------------------------------------------------- #
# Evidence                                                                      #
# --------------------------------------------------------------------------- #


@dataclass
class _Evidence:
    """The findings a response is built from, and where they came from."""

    source: str  # "scan", "client_supplied" or "none"
    scan_id: Optional[str] = None
    records: list = field(default_factory=list)
    total: int = 0

    def describe(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "scan_id": self.scan_id,
            "verified": self.source == "scan",
            "finding_count": self.total,
            "findings_in_prompt": len(self.records),
        }


class _EvidenceError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _get_db() -> DatabaseManager:
    if "db" not in g:
        g.db = DatabaseManager(os.environ["DATABASE_URL"])
        g.db.connect()
    return g.db


def _records(findings: list) -> list:
    ordered = sorted(findings, key=severity_rank, reverse=True)
    return [finding_record(f) for f in ordered[:_MAX_PROMPT_FINDINGS]]


def _resolve_evidence(body: dict, *, required: bool) -> _Evidence:
    """Return the findings this request should be answered from.

    ``required`` endpoints cannot produce anything useful without findings, so
    for them a missing scan is an error; optional ones fall back to no evidence.
    """
    supplied = body.get("findings")
    scan_id = body.get("scan_id")
    if supplied is not None and scan_id is not None:
        raise ValidationError("send either scan_id or findings, not both")

    if supplied is not None:
        findings = findings_list(supplied, required=required)
        logger.warning(
            "AI request used deprecated client-supplied findings (%d); send scan_id instead",
            len(findings),
        )
        return _Evidence("client_supplied", records=_records(findings), total=len(findings))

    if scan_id is not None:
        scan_id = uuid_string(scan_id, "scan_id")

    try:
        db = _get_db()
        if scan_id is not None:
            scan = db.get_scan(scan_id)
            if not scan or scan.get("status") != "completed":
                raise _EvidenceError(404, "Completed scan not found")
        else:
            scan = db.get_latest_completed_scan()
            if not scan:
                if required:
                    raise _EvidenceError(404, "No completed scan is available")
                return _Evidence("none")
        resolved_id = str(scan["scan_id"])
        findings = db.get_findings({"scan_id": resolved_id})
    except (_EvidenceError, ValidationError):
        raise
    except Exception as exc:
        logger.error("AI evidence lookup failed: %s", exc)
        if required or scan_id is not None:
            raise _EvidenceError(503, "Scan evidence is not available") from exc
        return _Evidence("none")

    if required and not findings:
        raise _EvidenceError(422, "The scan has no findings to analyse")
    return _Evidence("scan", scan_id=resolved_id, records=_records(findings), total=len(findings))


def _evidence_or_error(body: dict, *, required: bool):
    try:
        return _resolve_evidence(body, required=required), None
    except ValidationError:
        return None, (jsonify({"error": VALIDATION_ERROR_MESSAGE}), 400)
    except _EvidenceError as exc:
        return None, (jsonify({"error": exc.message}), exc.status)


# --------------------------------------------------------------------------- #
# Prompts                                                                       #
# --------------------------------------------------------------------------- #


def _findings_block(records: list, boundary: str) -> str:
    return data_block("FINDINGS", records, boundary)


def _knowledge_block(context: str, boundary: str) -> str:
    return data_block("KNOWLEDGE", context or "No grounded knowledge retrieved.", boundary)


def _build_summary_prompt(records: list, boundary: str) -> str:
    return (
        "You are a security advisor writing for a non-technical executive audience.\n"
        "Based on the cloud security findings below, write a concise executive summary.\n"
        "Avoid technical jargon. Mention the overall security risk level and likely business or operational impact.\n"
        "Do not invent findings. If information is missing, say so clearly.\n\n"
        f"{untrusted_data_rules(boundary)}"
        f"{_findings_block(records, boundary)}\n\n"
        "Executive Summary:"
    )


def _build_question_prompt(records: list, question: str, boundary: str) -> str:
    return (
        "You are a cloud security assistant.\n"
        "Answer the operator's question using only the scan findings provided.\n"
        "Do not invent facts or assume scan results that are not listed.\n"
        "Prioritise high severity, exploitable, and compliance-impacting findings, "
        "and consider remediation urgency.\n"
        "Be concise but useful. If the findings are insufficient to answer "
        "confidently, say what evidence is missing.\n\n"
        f"{untrusted_data_rules(boundary)}"
        f"{data_block('QUESTION', question, boundary)}\n\n"
        f"{_findings_block(records, boundary)}\n\n"
        "Answer:"
    )


def _build_remediation_prompt(records: list, boundary: str) -> str:
    return (
        "You are a cloud security engineer writing a remediation plan.\n"
        "The findings are already sorted by severity, most severe first.\n"
        "For each finding, provide practical, actionable fix steps.\n"
        "Reference the rule ID and title where available.\n"
        "Do not invent findings. If a finding lacks remediation detail, state what information is missing.\n\n"
        f"{untrusted_data_rules(boundary)}"
        f"{_findings_block(records, boundary)}\n\n"
        "Prioritised Remediation Plan:"
    )


def _build_grounded_summary_prompt(records: list, context: str, boundary: str) -> str:
    return (
        "You are a cloud security advisor. Using ONLY the grounded knowledge "
        "and the findings provided, write a plain English executive summary of the security "
        "posture for a non technical reader. Keep it under 120 words.\n\n"
        f"{untrusted_data_rules(boundary)}"
        f"{_knowledge_block(context, boundary)}\n\n"
        f"{_findings_block(records, boundary)}"
    )


def _build_prioritise_prompt(records: list, context: str, boundary: str) -> str:
    return (
        "You are a cloud security advisor. Using ONLY the grounded knowledge "
        "provided, rank the findings by real world exploitability and business "
        "risk, not just the severity label. Respond with valid JSON only, no "
        "markdown, as a list of objects with fields: priority (integer, 1 is most "
        "urgent), rule_id, rule_name, resource_name, severity, reason. Copy rule_id "
        "and resource_name exactly from the FINDINGS block.\n\n"
        f"{untrusted_data_rules(boundary)}"
        f"{_knowledge_block(context, boundary)}\n\n"
        f"{_findings_block(records, boundary)}"
    )


def _build_ask_prompt(records: list, context: str, question: str, boundary: str) -> str:
    findings = _findings_block(records, boundary) if records else "No findings were provided."
    return (
        "You are a cloud security advisor. Answer the operator's question using ONLY the "
        "grounded knowledge provided. If the answer is not in the knowledge, say "
        "so honestly. Reference specific rule IDs or controls where relevant.\n\n"
        f"{untrusted_data_rules(boundary)}"
        f"{_knowledge_block(context, boundary)}\n\n"
        f"{findings}\n\n"
        f"{data_block('QUESTION', question, boundary)}"
    )


def _build_threat_simulation_prompt(records: list, context: str, boundary: str) -> str:
    return (
        "You are a red team security analyst. Using the Azure cloud security "
        "findings and the grounded knowledge provided, construct a realistic "
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
        "- Map each stage to at least one rule_id from the FINDINGS block.\n"
        "- Do not invent findings or capabilities not present in the data.\n"
        "- If findings are insufficient for a full kill chain, only include supported stages.\n\n"
        f"{untrusted_data_rules(boundary)}"
        f"{_knowledge_block(context, boundary)}\n\n"
        f"{_findings_block(records, boundary)}"
    )


def _retrieval_query(records: list) -> str:
    """Build the knowledge-base query from rule identity only.

    Descriptions and resource names are left out: they are the untrusted part
    of a finding and should not steer which knowledge gets retrieved.
    """
    lines = [f"{r['rule_id']} {r['rule_name']}".strip() for r in records]
    return "\n".join(line for line in lines if line) or "Azure security posture"


def _context_for(query):
    chunks = retrieve(query, n_results=5)
    context = "\n".join(f"- ({c['source']}) {c['text']}" for c in chunks)
    # Extract structured source_meta for the frontend badges
    sources = [c["source_meta"] for c in chunks if c["source_meta"]]
    return context, sources


# --------------------------------------------------------------------------- #
# Request handling                                                              #
# --------------------------------------------------------------------------- #


def _read_request():
    try:
        body = require_json_object(request.get_json(silent=True))
        reject_unknown_fields(body, {"provider", "api_key", "model", "findings", "scan_id", "question"})
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


def _invalid_output_response(exc: AIResponseInvalid, log_context: str):
    logger.warning("%s: model output rejected: %s", log_context, exc)
    return jsonify({"error": "AI response failed validation"}), 502


@ai_bp.post("/api/ai/insights")
@rate_limit(_AI_RATE_LIMIT)
def insights():
    data, error = _read_request()
    if error:
        return error
    try:
        question = ""
        if data.get("question") is not None:
            if not isinstance(data["question"], str):
                raise ValidationError("question must be a string")
            if data["question"].strip():
                question = clean_question(bounded_string(data["question"], "question", maximum=MAX_QUESTION_LENGTH))
    except ValidationError:
        return jsonify({"error": VALIDATION_ERROR_MESSAGE}), 400

    evidence, error = _evidence_or_error(data, required=True)
    if error:
        return error

    provider = data["provider"]
    api_key = data["api_key"]
    boundary = new_boundary()
    try:
        executive_summary = get_completion(provider, api_key, _build_summary_prompt(evidence.records, boundary))
        remediation_plan = get_completion(provider, api_key, _build_remediation_prompt(evidence.records, boundary))
        answer = None
        if question:
            answer = get_completion(provider, api_key, _build_question_prompt(evidence.records, question, boundary))
    except Exception:
        logger.warning("AI provider request failed for provider=%s", provider)
        return jsonify({"error": "AI provider request failed"}), 502

    response = {
        "executive_summary": executive_summary,
        "remediation_plan": remediation_plan,
        "evidence": evidence.describe(),
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
    evidence, error = _evidence_or_error(body, required=False)
    if error:
        return error

    try:
        context, sources = _context_for(_retrieval_query(evidence.records))
    except VectorStoreNotBuilt as exc:
        return _ai_error_response(exc, 503, "Vector store unavailable in ai_summary")

    prompt = _build_grounded_summary_prompt(evidence.records, context, new_boundary())
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
            "evidence": evidence.describe(),
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
    evidence, error = _evidence_or_error(body, required=False)
    if error:
        return error

    response = {
        "prioritised_findings": [],
        "discarded_items": 0,
        "sources": [],
        "evidence": evidence.describe(),
        "provider": body["provider"],
        "model": body.get("model"),
    }
    if not evidence.records:
        # Nothing to rank; asking the model would only invite invented items.
        return jsonify(response)

    try:
        context, sources = _context_for(_retrieval_query(evidence.records))
    except VectorStoreNotBuilt as exc:
        return _ai_error_response(exc, 503, "Vector store unavailable in ai_prioritise")

    prompt = _build_prioritise_prompt(evidence.records, context, new_boundary())
    try:
        raw = get_completion(body["provider"], body["api_key"], prompt, model=body.get("model"))
    except ValueError as exc:
        return _ai_error_response(exc, 400, "Invalid request in ai_prioritise")
    except RuntimeError as exc:
        return _ai_error_response(exc, 502, "Provider failure in ai_prioritise")

    try:
        items, discarded = validate_prioritisation(parse_json_response(raw), evidence.records)
    except AIResponseInvalid as exc:
        return _invalid_output_response(exc, "ai_prioritise")

    response.update({"prioritised_findings": items, "discarded_items": discarded, "sources": sources})
    return jsonify(response)


@ai_bp.post("/api/ai/ask")
@rate_limit(_AI_RATE_LIMIT)
def ai_ask():
    body, error = _read_request()
    if error:
        return error
    try:
        question = clean_question(bounded_string(body.get("question"), "question", maximum=MAX_QUESTION_LENGTH))
    except ValidationError:
        return jsonify({"error": VALIDATION_ERROR_MESSAGE}), 400
    evidence, error = _evidence_or_error(body, required=False)
    if error:
        return error

    try:
        context, sources = _context_for(question)
    except VectorStoreNotBuilt as exc:
        return _ai_error_response(exc, 503, "Vector store unavailable in ai_ask")

    prompt = _build_ask_prompt(evidence.records, context, question, new_boundary())
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
            "evidence": evidence.describe(),
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
    evidence, error = _evidence_or_error(body, required=True)
    if error:
        return error

    try:
        context, sources = _context_for(_retrieval_query(evidence.records))
    except VectorStoreNotBuilt as exc:
        return _ai_error_response(exc, 503, "Vector store unavailable in ai_threat_simulation")

    prompt = _build_threat_simulation_prompt(evidence.records, context, new_boundary())
    try:
        raw = get_completion(body["provider"], body["api_key"], prompt, model=body.get("model"))
    except ValueError as exc:
        return _ai_error_response(exc, 400, "Invalid request in ai_threat_simulation")
    except RuntimeError as exc:
        return _ai_error_response(exc, 502, "Provider failure in ai_threat_simulation")

    try:
        simulation, discarded = validate_threat_simulation(parse_json_response(raw), evidence.records)
    except AIResponseInvalid as exc:
        return _invalid_output_response(exc, "ai_threat_simulation")

    return jsonify(
        {
            "threat_simulation": simulation,
            "discarded_items": discarded,
            "sources": sources,
            "evidence": evidence.describe(),
            "provider": body["provider"],
            "model": body.get("model"),
        }
    )
