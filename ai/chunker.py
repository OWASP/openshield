"""Chunking pipeline for OpenShield documents."""

import logging

logger = logging.getLogger(__name__)

DEFAULT_CHUNK_SIZE = 512
DEFAULT_CHUNK_OVERLAP = 64


def chunk_documents(documents, chunk_size=DEFAULT_CHUNK_SIZE, chunk_overlap=DEFAULT_CHUNK_OVERLAP):
    chunks = []
    for doc in documents:
        doc_id = doc.get("id", "unknown")
        content = doc.get("content", "")
        metadata = doc.get("metadata", {})
        doc_chunks = _split_text(content, chunk_size, chunk_overlap)
        for idx, chunk_text in enumerate(doc_chunks):
            chunks.append(
                {
                    "id": f"{doc_id}_chunk_{idx}",
                    "content": chunk_text,
                    "metadata": {
                        **metadata,
                        "parent_doc_id": doc_id,
                        "chunk_index": idx,
                        "total_chunks": len(doc_chunks),
                    },
                }
            )
    logger.info("Chunked %d documents into %d chunks", len(documents), len(chunks))
    return chunks


def _split_text(text, chunk_size, chunk_overlap):
    if len(text) <= chunk_size:
        return [text]
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        if end >= len(text):
            chunks.append(text[start:].strip())
            break
        split_pos = text.rfind("\n", start, end)
        if split_pos == -1 or split_pos <= start + chunk_overlap:
            split_pos = end
        chunk = text[start:split_pos].strip()
        if chunk:
            chunks.append(chunk)
        start = split_pos - chunk_overlap
        if start < 0:
            start = 0
    return [c for c in chunks if c]
