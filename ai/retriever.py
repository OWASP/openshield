"""Retrieve relevant OpenShield knowledge using BM25 scoring."""

import json
import logging
import math
import re
from pathlib import Path

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORSTORE_DIR = REPO_ROOT / "ai" / "vectorstore"
INDEX_PATH = VECTORSTORE_DIR / "bm25_index.json"

_BM25_K1 = 1.5
_BM25_B = 0.75

_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "but",
        "by",
        "for",
        "from",
        "had",
        "has",
        "have",
        "if",
        "in",
        "is",
        "it",
        "no",
        "not",
        "of",
        "on",
        "or",
        "so",
        "that",
        "the",
        "this",
        "to",
        "was",
        "were",
        "with",
    }
)


class VectorStoreNotBuilt(RuntimeError):
    """Raised when the BM25 index is missing or unreadable."""


def _tokenize(text: str) -> list:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) > 2 and t not in _STOPWORDS]


def _load_index() -> dict:
    if not INDEX_PATH.exists():
        raise VectorStoreNotBuilt("BM25 index not found. Run 'python -m ai.embed' first.")
    try:
        index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise VectorStoreNotBuilt(f"BM25 index unreadable: {exc}") from exc
    _validate_index(index)
    return index


def _validate_index(index: object) -> None:
    """Reject incompatible or malformed indexes before scoring."""

    def invalid(reason: str) -> None:
        raise VectorStoreNotBuilt(f"BM25 index invalid: {reason}")

    if not isinstance(index, dict):
        invalid("root must be an object")
    if index.get("version") != "1":
        invalid("unsupported or missing version")

    avg_dl = index.get("avg_dl")
    if isinstance(avg_dl, bool) or not isinstance(avg_dl, (int, float)) or not math.isfinite(avg_dl) or avg_dl <= 0:
        invalid("avg_dl must be a positive finite number")

    idf = index.get("idf")
    if not isinstance(idf, dict):
        invalid("idf must be an object")
    for term, value in idf.items():
        if (
            not isinstance(term, str)
            or isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
        ):
            invalid("idf entries must map terms to finite non-negative numbers")

    chunks = index.get("chunks")
    if not isinstance(chunks, list):
        invalid("chunks must be an array")
    for chunk in chunks:
        if not isinstance(chunk, dict):
            invalid("each chunk must be an object")
        if not isinstance(chunk.get("content"), str) or not isinstance(chunk.get("metadata"), dict):
            invalid("each chunk requires string content and object metadata")
        terms = chunk.get("terms")
        dl = chunk.get("dl")
        if not isinstance(terms, dict) or isinstance(dl, bool) or not isinstance(dl, int) or dl < 0:
            invalid("each chunk requires object terms and a non-negative integer dl")
        for term, frequency in terms.items():
            if (
                not isinstance(term, str)
                or isinstance(frequency, bool)
                or not isinstance(frequency, int)
                or frequency <= 0
            ):
                invalid("chunk terms must map tokens to positive integer frequencies")
        if sum(terms.values()) != dl:
            invalid("chunk term frequencies must sum to dl")


def _bm25_score(query_terms: list, doc_terms: dict, dl: int, avg_dl: float, idf: dict) -> float:
    score = 0.0
    for term in query_terms:
        tf = doc_terms.get(term, 0)
        if tf == 0:
            continue
        norm = tf * (_BM25_K1 + 1) / (tf + _BM25_K1 * (1 - _BM25_B + _BM25_B * dl / avg_dl))
        score += idf.get(term, 0.0) * norm
    return score


def retrieve(query: str, n_results: int = 5) -> list:
    """Return the most relevant knowledge chunks for a query.

    Each result is a dict with 'text', 'source', and 'source_meta'.
    """
    index = _load_index()
    avg_dl = index["avg_dl"]
    idf = index["idf"]
    query_terms = _tokenize(query)

    scored = []
    for chunk in index["chunks"]:
        score = _bm25_score(query_terms, chunk["terms"], chunk["dl"], avg_dl, idf)
        if score > 0:
            scored.append((score, chunk))

    scored.sort(key=lambda x: x[0], reverse=True)
    top = [chunk for _, chunk in scored[:n_results]]

    results = []
    for chunk in top:
        meta = chunk.get("metadata") or {}
        source_type = meta.get("source", "unknown")

        if source_type == "openShield_rule":
            source_id = meta.get("rule_id", "Rule")
            source_resource = meta.get("rule_name", "")
        elif source_type == "claude_red_skill":
            source_id = meta.get("skill_name", "Skill")
            source_resource = ""
        elif source_type == "compliance_framework":
            source_id = f"{meta.get('framework', 'Compliance')} {meta.get('control_id', '')}".strip()
            source_resource = meta.get("control_name", "")
        else:
            source_id = "General"
            source_resource = ""

        results.append(
            {
                "text": chunk["content"],
                "source": source_id,
                "source_meta": {
                    "id": source_id,
                    "type": source_type,
                    "resource": source_resource,
                    "file": meta.get("file", ""),
                },
            }
        )
    return results
