"""Build the OpenShield knowledge base BM25 index for RAG AI insights."""

import json
import logging
import math
import re
import sys
from pathlib import Path

from ai.chunker import chunk_documents
from ai.loader import load_all_documents

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORSTORE_DIR = REPO_ROOT / "ai" / "vectorstore"
INDEX_PATH = VECTORSTORE_DIR / "bm25_index.json"

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


def _tokenize(text: str) -> list:
    """Lowercase, split on non-alphanumeric, drop stopwords and short tokens."""
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) > 2 and t not in _STOPWORDS]


def build_vectorstore() -> int:
    """Build BM25 index from all documents and persist to JSON.

    Returns the number of chunks indexed.
    """
    documents = load_all_documents()
    if not documents:
        raise RuntimeError("No documents found to index. Check repo paths.")

    chunks = chunk_documents(documents)
    logger.info("Indexing %d chunks from %d source documents", len(chunks), len(documents))

    n = len(chunks)
    df: dict = {}
    processed = []

    for chunk in chunks:
        terms: dict = {}
        for token in _tokenize(chunk["content"]):
            terms[token] = terms.get(token, 0) + 1
        for token in terms:
            df[token] = df.get(token, 0) + 1
        processed.append(
            {
                "id": chunk["id"],
                "content": chunk["content"],
                "metadata": chunk["metadata"],
                "terms": terms,
                "dl": sum(terms.values()),
            }
        )

    avg_dl = sum(c["dl"] for c in processed) / n if n else 1.0

    idf = {term: math.log((n - freq + 0.5) / (freq + 0.5) + 1.0) for term, freq in df.items()}

    index = {"version": "1", "avg_dl": avg_dl, "idf": idf, "chunks": processed}

    VECTORSTORE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = INDEX_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(index, ensure_ascii=False), encoding="utf-8")
    tmp.replace(INDEX_PATH)

    logger.info("BM25 index written to %s (%d chunks)", INDEX_PATH, n)
    return n


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        count = build_vectorstore()
        print(f"Done. BM25 index built with {count} chunks at {INDEX_PATH}")
    except Exception as exc:
        print(f"Error building index: {exc}")
        sys.exit(1)
