"""ChromaDB cross-scan vulnerability memory store.

Stores confirmed findings as embeddings keyed by CWE+URL hash.
Retrieves similar past findings before each LLM classification call
so the agent builds institutional knowledge across scan sessions.

Uses mock embeddings in MOCK_LLM=true or CI=true mode.
"""

from __future__ import annotations

import hashlib
import logging
import os

logger = logging.getLogger(__name__)

MOCK_MODE = os.getenv("MOCK_LLM") == "true"
CI_MODE = os.getenv("CI") == "true"
USE_MOCK_EMBEDDINGS = MOCK_MODE or CI_MODE


def _build_embedding_function():
    """Return embedding function — mock for CI, Ollama for production."""
    if USE_MOCK_EMBEDDINGS:
        class MockEF:
            def name(self) -> str:
                return "mock"

            def __call__(self, input: list[str]) -> list[list[float]]:
                return self._embed(input)

            def embed_query(self, input: list[str]) -> list[list[float]]:
                return self._embed(input)

            def embed_documents(self, input: list[str]) -> list[list[float]]:
                return self._embed(input)

            def _embed(self, input: list[str]) -> list[list[float]]:
                return [[float(hash(t) % 1000) / 1000.0] * 384 for t in input]
        return MockEF()

    try:
        from chromadb.utils.embedding_functions import OllamaEmbeddingFunction
        return OllamaEmbeddingFunction(
            model_name="nomic-embed-text",
            url="http://localhost:11434/api/embeddings",
        )
    except Exception:
        class MockEF:
            def name(self) -> str:
                return "mock"

            def __call__(self, input: list[str]) -> list[list[float]]:
                return self._embed(input)

            def embed_query(self, input: list[str]) -> list[list[float]]:
                return self._embed(input)

            def embed_documents(self, input: list[str]) -> list[list[float]]:
                return self._embed(input)

            def _embed(self, input: list[str]) -> list[list[float]]:
                return [[float(hash(t) % 1000) / 1000.0] * 384 for t in input]
        return MockEF()


def _build_client():
    """Return ChromaDB client — in-memory for CI/mock, persistent otherwise."""
    import chromadb
    if USE_MOCK_EMBEDDINGS:
        return chromadb.Client()
    return chromadb.PersistentClient(path="./chroma_db")


def _get_collection():
    client = _build_client()
    ef = _build_embedding_function()
    return client.get_or_create_collection(
        name="vuln_memory",
        embedding_function=ef,
    )


def _finding_id(cweid: str, url: str) -> str:
    """Generate a stable ID from CWE ID + URL."""
    key = f"{cweid}:{url}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def store_finding(
    alert: dict,
    assessment: dict,
) -> None:
    """Embed and upsert a confirmed finding into the vector store."""
    collection = _get_collection()
    cweid = alert.get("cweid", "unknown")
    url = alert.get("url", "")
    doc_id = _finding_id(cweid, url)

    doc = (
        f"Alert: {alert.get('alert', 'unknown')}. "
        f"CWE: {cweid}. "
        f"URL: {url}. "
        f"Severity: {assessment.get('adjusted_severity', 'unknown')}. "
        f"False positive: {assessment.get('is_false_positive', False)}. "
        f"Note: {assessment.get('analyst_note', '')}."
    )

    existing = collection.get(ids=[doc_id])
    if existing["ids"]:
        collection.update(
            ids=[doc_id],
            documents=[doc],
            metadatas=[{
                "cweid": cweid,
                "url": url,
                "is_false_positive": str(assessment.get("is_false_positive", False)),
                "adjusted_severity": assessment.get("adjusted_severity", "unknown"),
            }],
        )
    else:
        collection.add(
            ids=[doc_id],
            documents=[doc],
            metadatas=[{
                "cweid": cweid,
                "url": url,
                "is_false_positive": str(assessment.get("is_false_positive", False)),
                "adjusted_severity": assessment.get("adjusted_severity", "unknown"),
            }],
        )
    logger.info("Stored finding: %s @ %s", alert.get("alert"), url)


def recall_similar(alert: dict, n: int = 3) -> list[str]:
    """Retrieve top-n most similar past findings for context."""
    collection = _get_collection()
    count = collection.count()
    if count == 0:
        return []

    query = (
        f"{alert.get('alert', '')} "
        f"CWE {alert.get('cweid', '')} "
        f"{alert.get('url', '')}"
    )
    n_results = min(n, count)
    results = collection.query(
        query_texts=[query],
        n_results=n_results,
    )
    return results["documents"][0] if results["documents"] else []


if __name__ == "__main__":
    alert = {
        "alert": "SQL Injection",
        "cweid": "89",
        "url": "http://juice-shop:3000/rest/user/login",
    }
    assessment = {
        "is_false_positive": False,
        "adjusted_severity": "HIGH",
        "analyst_note": "SQL injection on login endpoint confirmed.",
    }
    store_finding(alert, assessment)
    similar = recall_similar(alert)
    print("Similar findings:", similar)
