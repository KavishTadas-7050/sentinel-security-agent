"""Tests for Day 14 — ZAP client wrapper (mock mode)."""

import pytest


@pytest.fixture(autouse=True)
def mock_zap_env(monkeypatch):
    """All tests run with MOCK_ZAP=true — no Docker needed."""
    monkeypatch.setenv("MOCK_ZAP", "true")
    # Reload module to pick up env var
    import importlib
    import agent.zap_wrapper as zw
    importlib.reload(zw)


def test_get_version_returns_string():
    from agent.zap_wrapper import ZAPClient
    client = ZAPClient()
    version = client.get_version()
    assert isinstance(version, str)
    assert len(version) > 0


def test_start_spider_returns_scan_id():
    from agent.zap_wrapper import ZAPClient
    client = ZAPClient()
    scan_id = client.start_spider("http://localhost:3000")
    assert isinstance(scan_id, str)


def test_get_crawl_map_returns_urls():
    from agent.zap_wrapper import ZAPClient
    client = ZAPClient()
    urls = client.get_crawl_map()
    assert isinstance(urls, list)
    assert len(urls) >= 10


def test_get_alerts_returns_list():
    from agent.zap_wrapper import ZAPClient
    client = ZAPClient()
    alerts = client.get_alerts()
    assert isinstance(alerts, list)
    assert len(alerts) > 0


def test_alert_schema():
    from agent.zap_wrapper import ZAPClient
    client = ZAPClient()
    alerts = client.get_alerts()
    for alert in alerts:
        assert "alert" in alert
        assert "risk" in alert
        assert "url" in alert
        assert alert["risk"] in ("High", "Medium", "Low", "Informational")


def test_run_full_scan_returns_expected_keys():
    from agent.zap_wrapper import ZAPClient
    client = ZAPClient()
    result = client.run_full_scan()
    assert "urls_found" in result
    assert "crawl_map" in result
    assert "alerts" in result
    assert "zap_version" in result
    assert result["urls_found"] >= 10


def test_spider_smoke_test_passes_in_mock_mode():
    """smoke_test_spider.py main() completes without assertion errors."""
    import scripts.smoke_test_spider as smoke
    smoke.main()
