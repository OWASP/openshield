# OpenShield RAG Pipeline

Document loader and chunker for OpenShield rules and compliance frameworks.
Loads all scanner rules and CIS, NIST, ISO 27001 and SOC2 controls
into structured documents for the RAG BM25 index.

The RAG pipeline has no optional dependencies. Everything runs on the Python
standard library (`math`, `json`, `re`). No C extensions, no chromadb, no numpy.

## Files

- `ai/loader.py` — loads OpenShield rules and compliance frameworks as structured documents
- `ai/chunker.py` — splits documents into overlapping chunks for indexing
- `ai/embed.py` — builds the BM25 index at `ai/vectorstore/bm25_index.json`
- `ai/retriever.py` — queries the index using BM25 term scoring

## Building the index

```bash
python -m ai.embed
```

The index is written atomically to `ai/vectorstore/bm25_index.json` so a
partial build never leaves a corrupt file.

## How loader.py works

Reads all `scanner/rules/az_*.py` files and extracts:
- Rule ID, name, severity, category
- Description and remediation text

Also reads all four compliance framework JSON files:
- CIS Azure Benchmark
- NIST CSF
- ISO 27001
- SOC2

Finally, it reads all Claude-Red AI skills from `ai/knowledge/skills/*.md`:
- Extracts the full markdown content as a document for offensive methodology knowledge.
- **Dynamic Grounding:** Automatically injects relevant OpenShield scanner rules into each skill document using the mapping registry at `ai/knowledge/rule_mapping.json`.

## How chunker.py works

Splits documents into 512-character overlapping chunks with 64-character
overlap. Tries to split on newlines to avoid breaking mid-sentence.
Each chunk inherits the metadata of its parent document.

## How BM25 works

At build time (`embed.py`):
1. Tokenizes each chunk (lowercase, non-alphanumeric split, stopword filter)
2. Computes per-term document frequency and IDF across the corpus
3. Stores term frequencies per chunk alongside the corpus statistics

At query time (`retriever.py`):
1. Tokenizes the query
2. Scores each chunk with the BM25 formula (k1=1.5, b=0.75)
3. Returns the top-N chunks sorted by score
