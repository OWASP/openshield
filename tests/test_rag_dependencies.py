"""Regression tests for the RAG dependency and embedding configuration."""

import json
from pathlib import Path
import subprocess
import sys

import pytest


def test_dockerfile_starts_with_from_instruction():
    dockerfile = Path("Dockerfile").read_bytes()

    assert dockerfile.startswith(b"FROM "), (
        "Dockerfile must start directly with FROM; a UTF-8 BOM makes the first Docker instruction invalid"
    )


def test_chunker_advances_when_newline_is_inside_overlap_window():
    script = (
        "from ai.chunker import _split_text; "
        "chunks = _split_text('abcdefghijklmno\\n' + 'x' * 30, 20, 10); "
        "assert ''.join(chunks).replace(' ', ''); print(len(chunks))"
    )

    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=2,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


def test_vulnerable_transformer_stack_is_not_installed():
    requirements = Path("requirements.txt").read_text(encoding="utf-8").lower()

    assert "sentence-transformers" not in requirements
    assert "transformers" not in requirements


def test_chromadb_absent_from_all_requirements():
    for req_file in Path(".").glob("requirements*.txt"):
        content = req_file.read_text(encoding="utf-8").lower()
        assert "chromadb" not in content, (
            f"chromadb must not appear in {req_file} "
            "(CVE-2026-45830 tenant-isolation bypass, CVE-2026-45833 RCE); "
            "the RAG pipeline now uses a pure-Python BM25 index with no C extensions"
        )


def test_requirements_ai_txt_does_not_exist():
    assert not Path("requirements-ai.txt").exists(), (
        "requirements-ai.txt must be deleted; chromadb has been replaced by the "
        "pure-Python BM25 index in ai/embed.py and ai/retriever.py"
    )


def test_bm25_retriever_tokenizer():
    from ai.retriever import _tokenize

    tokens = _tokenize("Azure Storage Account immutability policy")
    assert "azure" in tokens
    assert "storage" in tokens
    assert "immutability" in tokens
    assert "policy" in tokens
    # stopwords filtered
    assert "the" not in tokens
    assert "and" not in tokens


def test_bm25_score_zero_for_no_overlap():
    from ai.retriever import _bm25_score

    score = _bm25_score(["kubernetes"], {"azure": 2, "storage": 1}, dl=3, avg_dl=3.0, idf={"azure": 1.0})
    assert score == 0.0


def test_bm25_score_positive_for_matching_term():
    from ai.retriever import _bm25_score

    idf = {"storage": 2.0}
    score = _bm25_score(["storage"], {"storage": 3}, dl=5, avg_dl=5.0, idf=idf)
    assert score > 0.0


def test_bm25_score_higher_for_more_matches():
    from ai.retriever import _bm25_score

    idf = {"storage": 1.5, "immutable": 1.2}
    score_one = _bm25_score(["storage"], {"storage": 2, "immutable": 1}, dl=3, avg_dl=3.0, idf=idf)
    score_two = _bm25_score(["storage", "immutable"], {"storage": 2, "immutable": 1}, dl=3, avg_dl=3.0, idf=idf)
    assert score_two > score_one


def test_numpy_not_required():
    requirements = Path("requirements.txt").read_text(encoding="utf-8").lower()
    assert "numpy" not in requirements, "numpy must not be in requirements.txt; BM25 retrieval uses only stdlib math"


def test_bm25_index_builds_and_retrieves_openshield_content(tmp_path, monkeypatch):
    from ai import embed, retriever

    index_path = tmp_path / "bm25_index.json"
    documents = [
        {
            "id": "AZ-STOR-TEST",
            "content": "Azure storage accounts should require secure transfer and disable public access.",
            "metadata": {
                "source": "openShield_rule",
                "rule_id": "AZ-STOR-TEST",
                "rule_name": "Secure Azure storage",
            },
        },
        {
            "id": "AZ-ID-TEST",
            "content": "Privileged identities should use multifactor authentication and limited role assignments.",
            "metadata": {
                "source": "openShield_rule",
                "rule_id": "AZ-ID-TEST",
                "rule_name": "Protect privileged identities",
            },
        },
    ]
    monkeypatch.setattr(embed, "VECTORSTORE_DIR", tmp_path)
    monkeypatch.setattr(embed, "INDEX_PATH", index_path)
    monkeypatch.setattr(embed, "load_all_documents", lambda: documents)
    monkeypatch.setattr(retriever, "INDEX_PATH", index_path)

    assert embed.build_vectorstore() > 0

    results = retriever.retrieve("Azure storage account security", n_results=5)

    assert results
    assert results[0]["source"] == "AZ-STOR-TEST"
    assert all(result["text"] for result in results)
    assert all(result["source"] for result in results)


@pytest.mark.parametrize(
    "index",
    [
        {},
        {"version": "2", "avg_dl": 1.0, "idf": {}, "chunks": []},
        {"version": "1", "avg_dl": 0, "idf": {}, "chunks": []},
        {"version": "1", "avg_dl": 1.0, "idf": [], "chunks": []},
        {"version": "1", "avg_dl": 1.0, "idf": {}, "chunks": [{}]},
    ],
)
def test_malformed_bm25_index_raises_vector_store_not_built(tmp_path, monkeypatch, index):
    from ai import retriever

    index_path = tmp_path / "bm25_index.json"
    index_path.write_text(json.dumps(index), encoding="utf-8")
    monkeypatch.setattr(retriever, "INDEX_PATH", index_path)

    with pytest.raises(retriever.VectorStoreNotBuilt, match="BM25 index invalid"):
        retriever.retrieve("Azure storage")
