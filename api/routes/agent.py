"""Agent route: POST /api/agent/query — natural-language CSPM Q&A."""

import logging
import os

from flask import Blueprint, g, jsonify, request

from api.agent.agent import run_agent
from api.models.finding import DatabaseManager
from api.rate_limit import rate_limit

agent_bp = Blueprint("agent", __name__)
logger = logging.getLogger(__name__)


def _get_db() -> DatabaseManager:
    if "db" not in g:
        g.db = DatabaseManager(os.environ["DATABASE_URL"])
        g.db.connect()
    return g.db


@agent_bp.post("/api/agent/query")
@rate_limit(max_requests=20, window_seconds=60)
def agent_query():
    """Answer a natural-language CSPM question using the ReAct agent loop.

    Request body:
        question  (str, required) -- the user's question
        framework (str, optional) -- compliance framework context

    Returns 200 with answer, tools_used, iterations, confidence on success.
    """
    body = request.get_json(silent=True) or {}

    question = body.get("question", "")
    if not isinstance(question, str) or not question.strip():
        return jsonify({"error": "question is required"}), 400

    provider = os.environ.get("AI_PROVIDER", "anthropic")
    api_key = os.environ.get("AI_API_KEY", "")
    model = os.environ.get("AI_MODEL")  # None means provider uses its default

    if not api_key:
        return jsonify({"error": "AI provider not configured"}), 503

    tenant_id = getattr(g, "tenant_id", None) or ""
    subscription_id = getattr(g, "subscription_id", None) or ""

    try:
        db = _get_db()
        result = run_agent(
            question=question,
            subscription_id=subscription_id,
            tenant_id=tenant_id,
            db_conn=db.conn,
            provider=provider,
            api_key=api_key,
            model=model,
        )
    except Exception:
        logger.exception("Unexpected error in agent_query")
        return jsonify({"error": "internal server error"}), 500

    return jsonify(
        {
            "answer": result["answer"],
            "tools_used": result["tools_used"],
            "iterations": result["iterations"],
            "confidence": result["confidence"],
        }
    ), 200
