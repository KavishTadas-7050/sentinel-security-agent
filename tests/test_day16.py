"""Tests for Day 16 — crawl graph, graph pre-filter, and vuln memory."""

import pytest


@pytest.fixture(autouse=True)
def mock_env(monkeypatch):
    monkeypatch.setenv("MOCK_LLM", "true")
    monkeypatch.setenv("MOCK_ZAP", "true")
    monkeypatch.setenv("CI", "true")


CRAWL_URLS = [
    "http://juice-shop:3000/",
    "http://juice-shop:3000/login",
    "http://juice-shop:3000/register",
    "http://juice-shop:3000/rest/user/login",
    "http://juice-shop:3000/api/Products",
    "http://juice-shop:3000/rest/products/search",
]


def test_build_crawl_graph_creates_nodes():
    from agent.crawl_graph import build_crawl_graph
    g = build_crawl_graph(CRAWL_URLS)
    assert g is not None
    assert g.number_of_nodes() > 0


def test_is_reachable_for_crawled_url():
    from agent.crawl_graph import build_crawl_graph, is_reachable
    g = build_crawl_graph(CRAWL_URLS)
    assert is_reachable(g, "http://juice-shop:3000/login") is True


def test_is_not_reachable_for_uncrawled_url():
    from agent.crawl_graph import build_crawl_graph, is_reachable
    g = build_crawl_graph(CRAWL_URLS)
    assert is_reachable(g, "http://juice-shop:3000/administration/panel") is False


def test_graph_suppression_skips_llm():
    """Alert on uncrawled URL returns suppressed_by=graph_check instantly."""
    from agent.crawl_graph import build_crawl_graph
    from agent.vuln_classifier import classify_vulnerability

    g = build_crawl_graph(CRAWL_URLS)
    alert = {
        "alert": "XSS",
        "risk": "High",
        "confidence": "Medium",
        "url": "http://juice-shop:3000/administration/panel",
        "description": "XSS found",
        "solution": "Encode output",
        "cweid": "79",
    }
    result = classify_vulnerability(alert, CRAWL_URLS, crawl_graph=g)
    assert result["suppressed_by"] == "graph_check"
    assert result["is_false_positive"] is True
    assert result["reachable_in_crawl"] is False


def test_reachable_url_goes_to_llm():
    """Alert on crawled URL does NOT get graph-suppressed."""
    from agent.crawl_graph import build_crawl_graph
    from agent.vuln_classifier import classify_vulnerability

    g = build_crawl_graph(CRAWL_URLS)
    alert = {
        "alert": "SQL Injection",
        "risk": "High",
        "confidence": "Medium",
        "url": "http://juice-shop:3000/rest/user/login",
        "description": "SQL injection possible",
        "solution": "Parameterize queries",
        "cweid": "89",
    }
    result = classify_vulnerability(alert, CRAWL_URLS, crawl_graph=g)
    assert result.get("suppressed_by") != "graph_check"
    assert "is_false_positive" in result


def test_vuln_memory_store_and_recall():
    from agent.vuln_memory import store_finding, recall_similar

    alert = {
        "alert": "SQL Injection",
        "cweid": "89",
        "url": "http://juice-shop:3000/rest/user/login",
    }
    assessment = {
        "is_false_positive": False,
        "adjusted_severity": "HIGH",
        "analyst_note": "Confirmed SQL injection on login.",
    }
    store_finding(alert, assessment)
    results = recall_similar(alert, n=3)
    assert isinstance(results, list)


def test_vuln_memory_empty_store_returns_empty():
    from agent.vuln_memory import recall_similar
    results = recall_similar({"alert": "XSS", "cweid": "79", "url": "http://example.com"})
    assert isinstance(results, list)


def test_classify_all_with_graph():
    """Full batch with graph enabled — uncrawled URLs get suppressed."""
    from agent.zap_wrapper import ZAPClient
    from agent.vuln_classifier import classify_all_alerts

    client = ZAPClient()
    alerts = client.get_alerts()
    crawl_map = client.get_crawl_map()

    results = classify_all_alerts(alerts, crawl_map, use_graph=True)
    assert len(results) == len(alerts)
    for r in results:
        assert "is_false_positive" in r
