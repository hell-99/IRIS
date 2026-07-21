"""
LangGraph investigation agent.

Given a flagged detection, runs a 4-node graph: fetch the detection,
retrieve semantically similar past detections (RAG, via semantic_search),
retrieve relevant MITRE ATLAS TTP context, then has a local LLM generate
a natural-language explanation grounded in that retrieved context.
"""
import math
import sqlite3
from typing import TypedDict

import ollama
from langgraph.graph import StateGraph, END

from config import MITRE_ATLAS_TTPS
from rag.semantic_search import search_similar, _divergence_doc_text, _embed

CHAT_MODEL = "llama3.1:8b"
# Calibrated by hand, not guessed: nomic-embed-text has a real baseline similarity floor,
# 5 unrelated sentences ("the weather is sunny", grocery lists, etc.) scored 0.45-0.553
# against the 5 MITRE ATLAS categories below. Real flagged detections in this dataset
# scored 0.583-0.758. 0.60 sits in that gap, above the noise floor, below the real median.
MITRE_MATCH_THRESHOLD = 0.60

_mitre_embeddings = None


def _get_mitre_embeddings() -> dict:
    """Embed each MITRE ATLAS category once (5 categories, cheap), cache in memory."""
    global _mitre_embeddings
    if _mitre_embeddings is None:
        _mitre_embeddings = {}
        for key, val in MITRE_ATLAS_TTPS.items():
            text = f"{key.replace('_', ' ')}: {val['name']} ({val['tactic']})"
            _mitre_embeddings[key] = _embed(text)
    return _mitre_embeddings


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


class InvestigationState(TypedDict):
    db_path: str
    session_id: str
    detection: dict
    similar: list
    mitre_context: str
    explanation: str


def _fetch_detection(state: InvestigationState) -> InvestigationState:
    con = sqlite3.connect(state["db_path"])
    con.row_factory = sqlite3.Row
    row = con.execute(
        "SELECT * FROM divergence_analysis WHERE session_id = ?", (state["session_id"],)
    ).fetchone()
    con.close()
    state["detection"] = dict(row) if row else {}
    return state


def _retrieve_similar(state: InvestigationState) -> InvestigationState:
    if not state["detection"]:
        state["similar"] = []
        return state
    query = _divergence_doc_text(state["detection"])
    results = search_similar(state["db_path"], query, top_k=4)
    state["similar"] = [
        r for r in results if r["metadata"].get("session_id") != state["session_id"]
    ][:3]
    return state


def _retrieve_mitre_context(state: InvestigationState) -> InvestigationState:
    d = state["detection"]
    reason = d.get("sensitivity_reason") or ""
    if not reason:
        state["mitre_context"] = "No sensitivity_reason recorded for this detection"
        return state

    query_text = f"{reason}. Task: {d.get('task', '')}"
    query_embedding = _embed(query_text)
    mitre_embeddings = _get_mitre_embeddings()

    scored = sorted(
        (
            (key, _cosine_similarity(query_embedding, emb))
            for key, emb in mitre_embeddings.items()
        ),
        key=lambda x: x[1],
        reverse=True,
    )
    best_key, best_score = scored[0]

    if best_score >= MITRE_MATCH_THRESHOLD:
        val = MITRE_ATLAS_TTPS[best_key]
        state["mitre_context"] = (
            f"{val['id']} ({val['name']}, tactic: {val['tactic']}), "
            f"semantic similarity {round(best_score, 3)}"
        )
    else:
        state["mitre_context"] = (
            f"No confident MITRE ATLAS match (closest: {best_key}, "
            f"similarity {round(best_score, 3)}, below {MITRE_MATCH_THRESHOLD} threshold)"
        )
    return state


def _generate_explanation(state: InvestigationState) -> InvestigationState:
    d = state["detection"]
    if not d:
        state["explanation"] = "Detection not found."
        return state

    similar_text = "\n".join(f"- {r['document'][:200]}" for r in state["similar"]) or \
        "No similar past detections found."

    prompt = f"""You are a security analyst assistant. Explain in 3-4 concise sentences why this agent action was flagged as suspicious. Be specific about what happened and why it is risky. Reference the similar past incidents only if genuinely relevant, do not force a connection.

Detection:
Task: {d.get('task')}
Agent role: {d.get('agent_role')}
Expected tools: {d.get('expected_tools')}
Actual tools: {d.get('actual_tools')}
Reason flagged: {d.get('sensitivity_reason')}
Divergence score: {d.get('divergence_score')}

Possible MITRE ATLAS context: {state['mitre_context']}

Similar past incidents:
{similar_text}
"""
    resp = ollama.chat(model=CHAT_MODEL, messages=[{"role": "user", "content": prompt}])
    state["explanation"] = resp["message"]["content"]
    return state


def _build_graph():
    graph = StateGraph(InvestigationState)
    graph.add_node("fetch_detection", _fetch_detection)
    graph.add_node("retrieve_similar", _retrieve_similar)
    graph.add_node("retrieve_mitre_context", _retrieve_mitre_context)
    graph.add_node("generate_explanation", _generate_explanation)

    graph.set_entry_point("fetch_detection")
    graph.add_edge("fetch_detection", "retrieve_similar")
    graph.add_edge("retrieve_similar", "retrieve_mitre_context")
    graph.add_edge("retrieve_mitre_context", "generate_explanation")
    graph.add_edge("generate_explanation", END)
    return graph.compile()


_compiled_graph = None


def investigate(db_path: str, session_id: str) -> dict:
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = _build_graph()

    result = _compiled_graph.invoke({
        "db_path": db_path,
        "session_id": session_id,
        "detection": {},
        "similar": [],
        "mitre_context": "",
        "explanation": "",
    })
    return {
        "session_id": session_id,
        "found": bool(result["detection"]),
        "explanation": result["explanation"],
        "similar_incidents": result["similar"],
        "mitre_context": result["mitre_context"],
    }
