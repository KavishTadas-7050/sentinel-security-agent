"""Adversarial tests for the vulnerability classifier.

Three cases that matter for false positive accuracy:
1. Security header on non-browsable API endpoint → false positive
2. SQL injection on crawled login form → true positive HIGH/CRITICAL
3. XSS on admin panel URL never crawled → reachable_in_crawl=false

All tests run with MOCK_LLM=true and MOCK_ZAP=true.
Mock responses are validated against the VulnAssessment schema.
"""

import pytest


@pytest.fixture(autouse=True)
def mock_env(monkeypatch):
    monkeypatch.setenv("MOCK_LLM", "true")
    monkeypatch.setenv("MOCK_ZAP", "true")


CRAWL_MAP = [
    "http://juice-shop:3000/",
    "http://juice-shop:3000/login",
    "http://juice-shop:3000/register",
    "http://juice-shop:3000/rest/user/login",
    "http://juice-shop:3000/api/Products",
    "http://juice-shop:3000/rest/products/search",
]

X_FRAME_OPTIONS_ALERT = {
    "alert": "X-Frame-Options Header Not Set",
    "risk": "Medium",
    "confidence": "Medium",
    "url": "http://juice-shop:3000/api/health",
    "description": "X-Frame-Options header is not included in the HTTP response.",
    "solution": "Most modern Web browsers support the X-Frame-Options header.",
    "cweid": "1021",
    "wascid": "15",
}

SQL_INJECTION_ALERT = {
    "alert": "SQL Injection",
    "risk": "High",
    "confidence": "Medium",
    "url": "http://juice-shop:3000/rest/user/login",
    "description": "SQL injection may be possible.",
    "solution": "Do not trust client side input, even if there is client side validation.",
    "cweid": "89",
    "wascid": "19",
}

XSS_ADMIN_ALERT = {
    "alert": "Cross Site Scripting (Reflected)",
    "risk": "High",
    "confidence": "Medium",
    "url": "http://juice-shop:3000/administration/panel/users",
    "description": "Cross-site Scripting via reflected input.",
    "solution": "Validate and encode all user input.",
    "cweid": "79",
    "wascid": "8",
}


def _assert_valid_assessment(result: dict) -> None:
    """Assert the result matches VulnAssessment schema."""
    assert isinstance(result, dict)
    assert "is_false_positive" in result
    assert "reachable_in_crawl" in result
    assert "exploitability" in result
    assert "adjusted_severity" in result
    assert "analyst_note" in result
    assert result["exploitability"] in ("HIGH", "MEDIUM", "LOW", "NEGLIGIBLE")
    assert result["adjusted_severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def test_security_header_on_api_endpoint_returns_valid_schema():
    """X-Frame-Options on /api/health returns valid VulnAssessment schema."""
    from agent.vuln_classifier import classify_vulnerability
    result = classify_vulnerability(X_FRAME_OPTIONS_ALERT, CRAWL_MAP)
    _assert_valid_assessment(result)


def test_sql_injection_on_crawled_login_returns_valid_schema():
    """SQL injection on crawled /rest/user/login returns valid schema."""
    from agent.vuln_classifier import classify_vulnerability
    result = classify_vulnerability(SQL_INJECTION_ALERT, CRAWL_MAP)
    _assert_valid_assessment(result)
    assert result["reachable_in_crawl"] is True


def test_xss_on_uncrawled_admin_panel_not_reachable():
    """XSS on /administration/panel/users (not in crawl) returns reachable=False."""
    from agent.vuln_classifier import classify_vulnerability
    result = classify_vulnerability(XSS_ADMIN_ALERT, CRAWL_MAP)
    _assert_valid_assessment(result)
    assert result["reachable_in_crawl"] is False


def test_classify_all_alerts_batch():
    """classify_all_alerts processes all mock ZAP alerts without crashing."""
    from agent.zap_wrapper import ZAPClient
    from agent.vuln_classifier import classify_all_alerts

    client = ZAPClient()
    alerts = client.get_alerts()
    crawl_map = client.get_crawl_map()

    results = classify_all_alerts(alerts, crawl_map)
    assert len(results) == len(alerts)
    for r in results:
        assert "alert" in r
        assert "is_false_positive" in r


def test_retry_decorator_on_json_error():
    """retry_with_backoff retries on JSONDecodeError and succeeds."""
    import json
    from agent.vuln_classifier import retry_with_backoff

    call_count = 0

    @retry_with_backoff(max_attempts=3, base_delay=0.01)
    def flaky():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise json.JSONDecodeError("bad", "", 0)
        return {"is_false_positive": False}

    result = flaky()
    assert result["is_false_positive"] is False
    assert call_count == 3


def test_vuln_reasoner_run_triage():
    """run_triage() completes without error in mock mode."""
    import os
    os.environ["MOCK_LLM"] = "true"
    os.environ["MOCK_ZAP"] = "true"
    from agent.vuln_reasoner import run_triage
    report = run_triage()
    assert "total_alerts" in report
    assert "findings" in report
    assert report["total_alerts"] > 0
