"""
Semantic search over IRIS's own detection history.

Embeds suspicious divergence_analysis records and collusion_detections
using a local Ollama embedding model, stores them in a per-user Chroma
vector store (mirroring IRIS's existing per-user SQLite isolation), and
answers "find detections similar to X" queries by meaning rather than
exact text match.
"""
import pathlib
import sqlite3

import chromadb
import ollama

EMBED_MODEL = "nomic-embed-text"
COLLECTION_NAME = "iris_detections"


def _chroma_dir_for_db(db_path: str) -> str:
    p = pathlib.Path(db_path)
    return str(p.parent / f"{p.stem}_chroma")


def _get_collection(db_path: str):
    client = chromadb.PersistentClient(path=_chroma_dir_for_db(db_path))
    return client.get_or_create_collection(
        COLLECTION_NAME, metadata={"hnsw:space": "cosine"}
    )


def _embed(text: str) -> list[float]:
    return ollama.embeddings(model=EMBED_MODEL, prompt=text)["embedding"]


def _divergence_doc_text(row: dict) -> str:
    return (
        f"Task: {row.get('task', '')}\n"
        f"Agent role: {row.get('agent_role', '')}\n"
        f"Expected tools: {row.get('expected_tools', '')}\n"
        f"Actual tools: {row.get('actual_tools', '')}\n"
        f"Reason flagged: {row.get('sensitivity_reason') or 'none'}\n"
        f"Verdict: {row.get('verdict', '')}"
    )


def _collusion_doc_text(row: dict) -> str:
    return (
        f"Collusion pattern: {row.get('pattern_name', '')}\n"
        f"Severity: {row.get('severity', '')}\n"
        f"TTP: {row.get('ttp_id', '')}\n"
        f"Description: {row.get('description', '')}\n"
        f"Agent 1 ({row.get('agent_1_role', '')}) used {row.get('agent_1_tool', '')}\n"
        f"Agent 2 ({row.get('agent_2_role', '')}) used {row.get('agent_2_tool', '')}"
    )


def index_detections(db_path: str) -> dict:
    """(Re-)index all suspicious divergence and collusion records for this DB. Idempotent (upsert by stable id)."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    collection = _get_collection(db_path)

    indexed = 0
    for row in con.execute("SELECT * FROM divergence_analysis WHERE verdict='SUSPICIOUS'").fetchall():
        row = dict(row)
        text = _divergence_doc_text(row)
        collection.upsert(
            ids=[f"divergence_{row['session_id']}"],
            embeddings=[_embed(text)],
            documents=[text],
            metadatas=[{
                "type": "divergence",
                "session_id": row["session_id"],
                "verdict": row["verdict"],
                "timestamp": row.get("timestamp", ""),
            }],
        )
        indexed += 1

    for row in con.execute("SELECT * FROM collusion_detections").fetchall():
        row = dict(row)
        text = _collusion_doc_text(row)
        collection.upsert(
            ids=[f"collusion_{row['id']}"],
            embeddings=[_embed(text)],
            documents=[text],
            metadatas=[{
                "type": "collusion",
                "id": row["id"],
                "pattern_name": row.get("pattern_name", ""),
                "severity": row.get("severity", ""),
                "ttp_id": row.get("ttp_id", ""),
            }],
        )
        indexed += 1

    con.close()
    return {"indexed": indexed, "collection_count": collection.count()}


def search_similar(db_path: str, query: str, top_k: int = 5) -> list[dict]:
    """Semantic search: returns past detections whose meaning is closest to the query text."""
    collection = _get_collection(db_path)
    if collection.count() == 0:
        index_detections(db_path)
    if collection.count() == 0:
        return []

    query_embedding = _embed(query)
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=min(top_k, collection.count()),
    )

    out = []
    for doc, meta, dist in zip(
        results["documents"][0], results["metadatas"][0], results["distances"][0]
    ):
        out.append({
            "document": doc,
            "metadata": meta,
            "similarity": round(1 - dist, 4),  # cosine space: 1 - cosine_distance
        })
    return out
