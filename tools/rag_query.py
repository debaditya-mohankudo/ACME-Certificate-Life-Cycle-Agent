"""Query the RAG index — semantic search over PR descriptions + docs.

Part of the three-layer team memory POC. See memory/acme_team_memory_poc.md for
full setup, layer overview, and how to rebuild the index.

Usage:
    python tools/rag_query.py "how does JWS signing work"
    python tools/rag_query.py "why is storage atomic" --top 3
"""
import argparse
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

COLLECTION_NAME = "acme_team"
INDEX_DIR = Path(__file__).parent.parent / "rag_index"
EMBED_MODEL = "all-MiniLM-L6-v2"


def query(prompt: str, top_k: int = 5) -> str:
    if not INDEX_DIR.exists():
        return "RAG index not found. Run tools/rag_indexer.py first."

    client = chromadb.PersistentClient(path=str(INDEX_DIR))
    try:
        collection = client.get_collection(COLLECTION_NAME)
    except Exception:
        return "RAG index empty. Run tools/rag_indexer.py first."

    if collection.count() == 0:
        return "RAG index is empty. Run tools/rag_indexer.py first."

    model = SentenceTransformer(EMBED_MODEL)
    embedding = model.encode(prompt).tolist()

    results = collection.query(
        query_embeddings=[embedding],
        n_results=min(top_k, collection.count()),
        include=["documents", "metadatas", "distances"],
    )

    docs = results["documents"][0]
    metas = results["metadatas"][0]
    distances = results["distances"][0]

    if not docs:
        return f"No results found for: {prompt}"

    lines = []
    for i, (doc, meta, dist) in enumerate(zip(docs, metas, distances), 1):
        score = round(1 - dist, 3)
        lines.append(f"### [{i}] {meta['source']} — {meta['title']} (score: {score})")
        lines.append(doc.strip())
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("prompt")
    parser.add_argument("--top", type=int, default=5)
    args = parser.parse_args()
    print(query(args.prompt, top_k=args.top))
