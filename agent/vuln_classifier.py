"""LangChain vulnerability classifier chain with graph pre-filter and retry.

Pipeline:
1. Graph check (instant) — if URL not reachable from crawl root, suppress
2. LLM classification (slow) — only fires for reachable URLs
"""

from __future__ import annotations

import functools
import json
import logging
import time

from agent.llm_backend import get_llm
from agent.prompts import VULN_CLASSIFY_PROMPT, parser

logger = logging.getLogger(__name__)


def retry_with_backoff(max_attempts: int = 3, base_delay: float = 0.5):
    """Retry decorator with exponential backoff on JSON/parse errors."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except (json.JSONDecodeError, KeyError, ValueError) as exc:
                    last_exc = exc
                    if attempt == max_attempts - 1:
                        raise
                    wait = base_delay * (2 ** attempt)
                    logger.warning(
                        "classify attempt %d failed (%s), retrying in %.1fs",
                        attempt + 1, exc, wait,
                    )
                    time.sleep(wait)
            raise last_exc
        return wrapper
    return decorator


def _graph_suppression_result(alert: dict, reason: str) -> dict:
    """Return an instant suppression result without calling the LLM."""
    return {
        **alert,
        "is_false_positive": True,
        "false_positive_reason": reason,
        "reachable_in_crawl": False,
        "exploitability": "NEGLIGIBLE",
        "adjusted_severity": "INFO",
        "analyst_note": f"Suppressed by graph check: {reason}",
        "suppressed_by": "graph_check",
    }


@retry_with_backoff(max_attempts=3, base_delay=0.5)
def classify_vulnerability(
    alert: dict,
    crawl_map: list[str],
    crawl_graph=None,
) -> dict:
    """
    Classify a single ZAP alert.

    Fast path: if crawl_graph provided and URL not reachable → instant suppression.
    Slow path: LLM classification for reachable URLs.

    Args:
        alert:       ZAP alert dict
        crawl_map:   List of crawled URLs
        crawl_graph: Optional pre-built nx.DiGraph for fast reachability check

    Returns:
        VulnAssessment dict, possibly with suppressed_by='graph_check'
    """
    alert_url = alert.get("url", "")

    # Fast path: graph reachability check (no LLM cost)
    if crawl_graph is not None:
        from agent.crawl_graph import is_reachable
        if not is_reachable(crawl_graph, alert_url):
            logger.info(
                "Graph suppression: %s not reachable in crawl map", alert_url
            )
            return _graph_suppression_result(
                alert,
                f"URL {alert_url} not found in spider crawl map",
            )

    # Slow path: LLM classification
    crawl_sample = "\n".join(f"  - {u}" for u in crawl_map[:20])
    if not crawl_sample:
        crawl_sample = "  (no URLs in crawl map)"

    llm = get_llm()
    chain = VULN_CLASSIFY_PROMPT | llm | parser

    result = chain.invoke({
        "alert_name":   alert.get("alert", "Unknown"),
        "risk":         alert.get("risk", "Unknown"),
        "confidence":   alert.get("confidence", "Unknown"),
        "url":          alert_url,
        "description":  alert.get("description", "")[:500],
        "solution":     alert.get("solution", "")[:300],
        "cweid":        alert.get("cweid", "N/A"),
        "crawl_count":  len(crawl_map),
        "crawl_sample": crawl_sample,
    })
    return result


def classify_all_alerts(
    alerts: list[dict],
    crawl_map: list[str],
    use_graph: bool = True,
) -> list[dict]:
    """
    Classify every alert. Builds crawl graph once for the full batch.

    Returns list of dicts merging original alert with assessment fields.
    """
    crawl_graph = None
    if use_graph:
        from agent.crawl_graph import build_crawl_graph
        crawl_graph = build_crawl_graph(crawl_map)
        logger.info("Crawl graph built for batch classification")

    results = []
    llm_calls = 0
    graph_suppressed = 0

    for i, alert in enumerate(alerts):
        logger.info(
            "Classifying alert %d/%d: %s",
            i + 1, len(alerts), alert.get("alert", "?"),
        )
        try:
            assessment = classify_vulnerability(alert, crawl_map, crawl_graph)
            if assessment.get("suppressed_by") == "graph_check":
                graph_suppressed += 1
            else:
                llm_calls += 1
            results.append({**alert, **assessment})
        except Exception as exc:
            logger.error("Failed: %s — %s", alert.get("alert"), exc)
            results.append({**alert, "is_false_positive": None, "error": str(exc)})

    logger.info(
        "Batch complete: %d LLM calls, %d graph-suppressed",
        llm_calls, graph_suppressed,
    )
    return results


if __name__ == "__main__":
    import os
    os.environ["MOCK_LLM"] = "true"
    os.environ["MOCK_ZAP"] = "true"

    from agent.zap_wrapper import ZAPClient
    client = ZAPClient()
    alerts = client.get_alerts()
    crawl_map = client.get_crawl_map()

    results = classify_all_alerts(alerts, crawl_map, use_graph=True)
    print("\n=== CLASSIFICATION RESULTS ===")
    for r in results:
        fp = r.get("is_false_positive")
        suppressed = " [GRAPH]" if r.get("suppressed_by") == "graph_check" else ""
        status = "FP" if fp else "TP" if fp is False else "ERR"
        print(f"  [{status}][{r.get('adjusted_severity', '?')}]{suppressed} {r.get('alert')}")
