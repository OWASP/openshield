"""Unit tests for the RAG pipeline — ai/loader.py, ai/chunker.py, ai/retriever.py."""

from pathlib import Path
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# ai/loader.py tests
# ---------------------------------------------------------------------------


class TestLoader:
    """Tests for ai/loader.py document loading."""

    def test_load_rule_documents_returns_list(self):
        """load_rule_documents returns a non-empty list."""
        from ai.loader import load_rule_documents

        docs = load_rule_documents()
        assert isinstance(docs, list)
        assert len(docs) > 0

    def test_load_rule_documents_have_required_keys(self):
        """Each rule document has id, content and metadata keys."""
        from ai.loader import load_rule_documents

        docs = load_rule_documents()
        for doc in docs:
            assert "id" in doc
            assert "content" in doc
            assert "metadata" in doc

    def test_load_rule_documents_metadata_has_rule_id(self):
        """Each rule document metadata contains rule_id."""
        from ai.loader import load_rule_documents

        docs = load_rule_documents()
        for doc in docs:
            assert "rule_id" in doc["metadata"]
            assert doc["metadata"]["rule_id"].startswith("AZ-")

    def test_load_rule_documents_content_is_string(self):
        """Document content is a non-empty string."""
        from ai.loader import load_rule_documents

        docs = load_rule_documents()
        for doc in docs:
            assert isinstance(doc["content"], str)
            assert len(doc["content"]) > 0

    def test_load_compliance_documents_returns_list(self):
        """load_compliance_documents returns a non-empty list."""
        from ai.loader import load_compliance_documents

        docs = load_compliance_documents()
        assert isinstance(docs, list)
        assert len(docs) > 0

    def test_load_compliance_documents_have_framework(self):
        """Each compliance document metadata contains framework name."""
        from ai.loader import load_compliance_documents

        docs = load_compliance_documents()
        known_frameworks = {"CIS Azure Benchmark", "NIST CSF", "ISO 27001", "SOC2"}
        for doc in docs:
            assert doc["metadata"]["framework"] in known_frameworks

    def test_load_all_documents_combines_rules_and_compliance(self):
        """load_all_documents returns more docs than rules or compliance alone."""
        from ai.loader import load_all_documents, load_rule_documents, load_compliance_documents

        all_docs = load_all_documents()
        rules = load_rule_documents()
        compliance = load_compliance_documents()
        # load_all_documents also includes skill documents in addition to rules and compliance
        assert len(all_docs) >= len(rules) + len(compliance)
        assert len(all_docs) > len(rules)
        assert len(all_docs) > len(compliance)

    def test_load_rule_documents_ids_are_unique(self):
        """Each rule document has a unique id."""
        from ai.loader import load_rule_documents

        docs = load_rule_documents()
        ids = [doc["id"] for doc in docs]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# ai/chunker.py tests
# ---------------------------------------------------------------------------


class TestChunker:
    """Tests for ai/chunker.py document chunking."""

    def _make_doc(self, content, doc_id="test-doc"):
        return {
            "id": doc_id,
            "content": content,
            "metadata": {"source": "test", "rule_id": "AZ-TEST-001"},
        }

    def test_chunk_documents_returns_list(self):
        """chunk_documents returns a list."""
        from ai.chunker import chunk_documents

        docs = [self._make_doc("Short content")]
        chunks = chunk_documents(docs)
        assert isinstance(chunks, list)
        assert len(chunks) > 0

    def test_short_document_produces_one_chunk(self):
        """A document shorter than chunk_size produces exactly one chunk."""
        from ai.chunker import chunk_documents

        docs = [self._make_doc("Short content that fits in one chunk")]
        chunks = chunk_documents(docs, chunk_size=512)
        assert len(chunks) == 1

    def test_long_document_produces_multiple_chunks(self):
        """A document longer than chunk_size produces multiple chunks."""
        from ai.chunker import chunk_documents

        long_content = "word " * 300
        docs = [self._make_doc(long_content)]
        chunks = chunk_documents(docs, chunk_size=100, chunk_overlap=10)
        assert len(chunks) > 1

    def test_chunks_inherit_parent_metadata(self):
        """Each chunk inherits metadata from its parent document."""
        from ai.chunker import chunk_documents

        docs = [self._make_doc("content", doc_id="parent-doc")]
        chunks = chunk_documents(docs)
        for chunk in chunks:
            assert chunk["metadata"]["parent_doc_id"] == "parent-doc"
            assert chunk["metadata"]["source"] == "test"

    def test_chunks_have_unique_ids(self):
        """Each chunk has a unique id."""
        from ai.chunker import chunk_documents

        long_content = "word " * 300
        docs = [self._make_doc(long_content)]
        chunks = chunk_documents(docs, chunk_size=100, chunk_overlap=10)
        ids = [c["id"] for c in chunks]
        assert len(ids) == len(set(ids))

    def test_chunks_have_chunk_index(self):
        """Each chunk metadata contains chunk_index."""
        from ai.chunker import chunk_documents

        long_content = "word " * 300
        docs = [self._make_doc(long_content)]
        chunks = chunk_documents(docs, chunk_size=100, chunk_overlap=10)
        for i, chunk in enumerate(chunks):
            assert "chunk_index" in chunk["metadata"]

    def test_empty_documents_list(self):
        """chunk_documents handles empty input gracefully."""
        from ai.chunker import chunk_documents

        chunks = chunk_documents([])
        assert chunks == []

    def test_multiple_documents_chunked(self):
        """Multiple documents are all chunked."""
        from ai.chunker import chunk_documents

        docs = [
            self._make_doc("Content A", "doc-a"),
            self._make_doc("Content B", "doc-b"),
        ]
        chunks = chunk_documents(docs)
        parent_ids = {c["metadata"]["parent_doc_id"] for c in chunks}
        assert "doc-a" in parent_ids
        assert "doc-b" in parent_ids

    def test_chunk_overlap_content_is_shared(self):
        """Adjacent chunks share exactly the configured overlap characters."""
        from ai.chunker import chunk_documents

        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        long_content = (alphabet * 4)[:200]
        chunk_size = 80
        chunk_overlap = 20
        docs = [self._make_doc(long_content, "overlap-doc")]
        chunks = chunk_documents(docs, chunk_size=chunk_size, chunk_overlap=chunk_overlap)
        assert len(chunks) >= 2

        tail_of_first = chunks[0]["content"][-chunk_overlap:]
        head_of_second = chunks[1]["content"][:chunk_overlap]
        assert tail_of_first == head_of_second, (
            f"Expected {chunk_overlap} chars of overlap.\n"
            f"End of chunk 0: {repr(tail_of_first)}\n"
            f"Start of chunk 1: {repr(head_of_second)}"
        )

    def test_no_overlap_when_zero(self):
        """With chunk_overlap=0 the start of chunk[1] does not repeat chunk[0]."""
        from ai.chunker import chunk_documents

        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        long_content = (alphabet * 4)[:200]
        chunk_size = 60
        chunk_overlap = 0
        docs = [self._make_doc(long_content, "no-overlap-doc")]
        chunks = chunk_documents(docs, chunk_size=chunk_size, chunk_overlap=chunk_overlap)
        assert len(chunks) >= 2
        assert chunks[0]["content"][-5:] != chunks[1]["content"][:5]


# ---------------------------------------------------------------------------
# ai/retriever.py tests
# ---------------------------------------------------------------------------


class TestRetriever:
    """Tests for ai/retriever.py vector store retrieval."""

    def test_retrieve_raises_when_chromadb_missing(self):
        """retrieve raises VectorStoreNotBuilt when chromadb is unavailable."""
        from ai.retriever import retrieve, VectorStoreNotBuilt

        with patch("ai.retriever.chromadb", None):
            with pytest.raises(VectorStoreNotBuilt):
                retrieve("test query")

    def test_retrieve_raises_when_store_missing(self):
        """retrieve raises VectorStoreNotBuilt when vectorstore dir is missing."""
        from ai.retriever import retrieve, VectorStoreNotBuilt

        with patch("ai.retriever.VECTORSTORE_DIR", Path("/nonexistent/path")):
            with pytest.raises(VectorStoreNotBuilt):
                retrieve("test query")

    def test_vector_store_not_built_is_runtime_error(self):
        """VectorStoreNotBuilt is a subclass of RuntimeError."""
        from ai.retriever import VectorStoreNotBuilt

        assert issubclass(VectorStoreNotBuilt, RuntimeError)


# ---------------------------------------------------------------------------
# ai/embed.py tests
# ---------------------------------------------------------------------------


class TestEmbedPipeline:
    """Tests for ai/embed.py build_vectorstore() pipeline."""

    def test_build_vectorstore_raises_without_chromadb(self):
        """build_vectorstore() raises RuntimeError when chromadb is unavailable."""
        import ai.embed as embed

        original = embed.chromadb
        try:
            embed.chromadb = None
            with pytest.raises(RuntimeError, match="chromadb is not installed"):
                embed.build_vectorstore()
        finally:
            embed.chromadb = original

    def test_build_vectorstore_raises_when_no_documents(self):
        """build_vectorstore() raises RuntimeError when loader returns empty list."""
        from unittest.mock import patch
        import ai.embed as embed

        if embed.chromadb is None:
            pytest.skip("chromadb not installed")
        with patch("ai.embed.load_all_documents", return_value=[]):
            with pytest.raises(RuntimeError, match="No documents found"):
                embed.build_vectorstore()

    def test_build_vectorstore_full_pipeline(self):
        """build_vectorstore() creates collection, adds chunks, renames, returns count."""
        from unittest.mock import MagicMock, patch
        import ai.embed as embed

        if embed.chromadb is None:
            pytest.skip("chromadb not installed")

        mock_docs = [{"id": f"doc-{i}", "content": f"content {i}", "metadata": {}} for i in range(3)]
        mock_chunks = [{"id": f"chunk-{i}", "content": f"chunk {i}", "metadata": {}} for i in range(5)]

        mock_collection = MagicMock()
        mock_client = MagicMock()
        mock_client.create_collection.return_value = mock_collection

        with patch("ai.embed.load_all_documents", return_value=mock_docs):
            with patch("ai.embed.chunk_documents", return_value=mock_chunks):
                with patch("ai.embed.chromadb.PersistentClient", return_value=mock_client):
                    with patch("ai.embed.VECTORSTORE_DIR") as mock_dir:
                        mock_dir.mkdir = MagicMock()
                        result = embed.build_vectorstore()

        # Verify collection was created with temp name
        mock_client.create_collection.assert_called_once_with("openshield_temp")

        # Verify chunks were added to the collection
        mock_collection.add.assert_called()
        all_added_ids = []
        for c in mock_collection.add.call_args_list:
            all_added_ids.extend(c.kwargs.get("ids", c.args[0] if c.args else []))
        assert len(all_added_ids) == len(mock_chunks)

        # Verify atomic rename from temp to final collection name
        mock_collection.modify.assert_called_once_with(name="openshield")

        # Verify return value is chunk count
        assert result == len(mock_chunks)
