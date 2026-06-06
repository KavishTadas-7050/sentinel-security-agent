"""LangChain vulnerability classifier chain with retry backoff.

Classifies a single ZAP alert as true/false positive using the
VulnAssessment schema, injecting crawl map context for reachability.
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
                        "classify_vulnerability attempt %d failed (%s), retrying in %.1fs",
                        attempt + 1, exc, wait,
                    )
                    time.sleep(wait)
            raise last_exc
        return wrapper
    return decorator


@retry_with_backoff(max_attempts=3, base_delay=0.5)
def classify_vulnerability(alert: dict, crawl_map: list[str]) -> dict:
    """
    Classify a single ZAP alert against the crawl map.

    Args:
        alert:     A ZAP alert dict with keys: alert, risk, confidence,
                   url, description, solution, cweid
        crawl_map: List of URLs discovered by the spider

    Returns:
        VulnAssessment dict with is_false_positive, adjusted_severity, etc.
    """
    alert_url = alert.get("url", "")
    crawl_sample = "\n".join(f"  - {u}" for u in crawl_map[:20])
    if not crawl_sample:
        crawl_sample = "  (no URLs in crawl map)"

    llm = get_llm()
    chain = VULN_CLASSIFY_PROMPT | llm | parser

    return chain.invoke({
        "alert_name":  alert.get("alert", "Unknown"),
        "risk":        alert.get("risk", "Unknown"),
        "confidence":  alert.get("confidence", "Unknown"),
        "url":         alert_url,
        "description": alert.get("description", "")[:500],
        "solution":    alert.get("solution", "")[:300],
        "cweid":       alert.get("cweid", "N/A"),
        "crawl_count": len(crawl_map),
        "crawl_sample": crawl_sample,
    })


def classify_all_alerts(
    alerts: list[dict],
    crawl_map: list[str],
) -> list[dict]:
    """
    Classify every alert in the list.

    Returns list of dicts merging original alert with VulnAssessment fields.
    Failed classifications get is_false_positive=None and an error field.
    """
    results = []
    for i, alert in enumerate(alerts):
        logger.info(
            "Classifying alert %d/%d: %s",
            i + 1, len(alerts), alert.get("alert", "?"),
        )
        try:
            assessment = classify_vulnerability(alert, crawl_map)
            results.append({**alert, **assessment})
        except Exception as exc:
            logger.error("Failed to classify alert %s: %s", alert.get("alert"), exc)
            results.append({
                **alert,
                "is_false_positive": None,
                "error": str(exc),
            })
    return results


if __name__ == "__main__":
    import json
    import os
    os.environ["MOCK_LLM"] = "true"

    from agent.zap_wrapper import ZAPClient
    client = ZAPClient()
    alerts = client.get_alerts()
    crawl_map = client.get_crawl_map()

    print(f"Classifying {len(alerts)} alerts against {len(crawl_map)} crawled URLs...\n")
    results = classify_all_alerts(alerts, crawl_map)

    print("=== CLASSIFICATION RESULTS ===")
    for r in results:
        status = "FALSE POSITIVE" if r.get("is_false_positive") else "TRUE POSITIVE"
        print(f"[{r.get('adjusted_severity', '?')}] {status} — {r.get('alert')}")
        print(f"  URL: {r.get('url')}")
        print(f"  Note: {r.get('analyst_note')}")
        print()
