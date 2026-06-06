"""Vulnerability reasoner — batch classifies all ZAP alerts.

Orchestrates: ZAPClient → classify_all_alerts → filtered report.
Run directly for a full scan + triage:
    python agent/vuln_reasoner.py
"""

from __future__ import annotations

import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_triage(target_url: str | None = None) -> dict:
    """Run full ZAP scan and classify all alerts. Returns triage report."""
    from agent.zap_wrapper import ZAPClient
    from agent.vuln_classifier import classify_all_alerts

    target = target_url or os.getenv("TARGET_URL", "http://juice-shop:3000")
    client = ZAPClient()

    logger.info("Starting ZAP scan of %s", target)
    scan_results = client.run_full_scan(target)

    alerts = scan_results["alerts"]
    crawl_map = scan_results["crawl_map"]
    logger.info("Scan complete: %d alerts, %d URLs", len(alerts), len(crawl_map))

    classified = classify_all_alerts(alerts, crawl_map)

    true_positives = [r for r in classified if r.get("is_false_positive") is False]
    false_positives = [r for r in classified if r.get("is_false_positive") is True]
    errors = [r for r in classified if r.get("is_false_positive") is None]

    report = {
        "target": target,
        "zap_version": scan_results["zap_version"],
        "urls_crawled": scan_results["urls_found"],
        "total_alerts": len(alerts),
        "true_positives": len(true_positives),
        "false_positives": len(false_positives),
        "errors": len(errors),
        "findings": classified,
    }

    return report


if __name__ == "__main__":
    os.environ.setdefault("MOCK_LLM", "true")
    os.environ.setdefault("MOCK_ZAP", "true")

    report = run_triage()
    print("\n=== TRIAGE REPORT ===")
    print(f"Target:          {report['target']}")
    print(f"URLs crawled:    {report['urls_crawled']}")
    print(f"Total alerts:    {report['total_alerts']}")
    print(f"True positives:  {report['true_positives']}")
    print(f"False positives: {report['false_positives']}")
    print()
    for finding in report["findings"]:
        fp = finding.get("is_false_positive")
        status = "FP" if fp else "TP" if fp is False else "ERR"
        sev = finding.get("adjusted_severity", "?")
        print(f"  [{status}][{sev}] {finding.get('alert')} — {finding.get('url')}")
