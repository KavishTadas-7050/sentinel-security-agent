
"""ZAP REST API client wrapper.

Wraps every ZAP REST endpoint behind clean Python method names.
The agent never calls raw URLs — all ZAP knowledge lives here.

Set MOCK_ZAP=true to return realistic fake data without Docker.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

ZAP_URL = os.getenv("ZAP_URL", "http://localhost:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "sentinel-api-key")
TARGET_URL = os.getenv("TARGET_URL", "http://juice-shop:3000")
MOCK_ZAP = os.getenv("MOCK_ZAP", "false").lower() == "true"


class ZAPClient:
    """Clean Python interface to the ZAP REST API."""

    def __init__(
        self,
        zap_url: str = ZAP_URL,
        api_key: str = ZAP_API_KEY,
    ) -> None:
        self.zap_url = zap_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"X-ZAP-API-Key": self.api_key})

    def _get(self, path: str, params: dict | None = None) -> Any:
        """Make a GET request to the ZAP REST API."""
        url = f"{self.zap_url}/{path}"
        params = params or {}
        params["apikey"] = self.api_key
        response = self.session.get(url, params=params, timeout=30)
        response.raise_for_status()
        return response.json()

    def get_version(self) -> str:
        """Return the ZAP version string."""
        if MOCK_ZAP:
            return "2.14.0"
        result = self._get("JSON/core/view/version/")
        return result.get("version", "unknown")

    def start_spider(self, target_url: str = TARGET_URL) -> str:
        """Start a spider scan and return the scan ID."""
        if MOCK_ZAP:
            logger.info("Mock: starting spider on %s", target_url)
            return "1"
        result = self._get(
            "JSON/spider/action/scan/",
            {"url": target_url, "recurse": "true"},
        )
        scan_id = result.get("scan", "0")
        logger.info("Spider started: scan_id=%s", scan_id)
        return scan_id

    def get_spider_status(self, scan_id: str) -> int:
        """Return spider progress as integer 0–100."""
        if MOCK_ZAP:
            return 100
        result = self._get(
            "JSON/spider/view/status/",
            {"scanId": scan_id},
        )
        return int(result.get("status", 0))

    def wait_for_spider(self, scan_id: str, poll_interval: int = 5) -> None:
        """Block until the spider reaches 100% completion."""
        if MOCK_ZAP:
            logger.info("Mock: spider complete immediately")
            return
        logger.info("Waiting for spider scan_id=%s ...", scan_id)
        while True:
            status = self.get_spider_status(scan_id)
            logger.info("Spider progress: %d%%", status)
            if status >= 100:
                break
            time.sleep(poll_interval)
        logger.info("Spider complete")

    def get_crawl_map(self) -> list[str]:
        """Return list of all URLs found by the spider."""
        if MOCK_ZAP:
            return [
                "http://juice-shop:3000/",
                "http://juice-shop:3000/login",
                "http://juice-shop:3000/register",
                "http://juice-shop:3000/rest/user/login",
                "http://juice-shop:3000/api/Products",
                "http://juice-shop:3000/api/Users",
                "http://juice-shop:3000/api/BasketItems",
                "http://juice-shop:3000/rest/products/search",
                "http://juice-shop:3000/ftp/",
                "http://juice-shop:3000/redirect",
                "http://juice-shop:3000/score-board",
                "http://juice-shop:3000/privacy-policy",
            ]
        result = self._get("JSON/core/view/urls/")
        return result.get("urls", [])

    def start_active_scan(self, target_url: str = TARGET_URL) -> str:
        """Start an active scan and return the scan ID."""
        if MOCK_ZAP:
            logger.info("Mock: starting active scan on %s", target_url)
            return "1"
        result = self._get(
            "JSON/ascan/action/scan/",
            {"url": target_url, "recurse": "true"},
        )
        scan_id = result.get("scan", "0")
        logger.info("Active scan started: scan_id=%s", scan_id)
        return scan_id

    def get_active_scan_status(self, scan_id: str) -> int:
        """Return active scan progress as integer 0–100."""
        if MOCK_ZAP:
            return 100
        result = self._get(
            "JSON/ascan/view/status/",
            {"scanId": scan_id},
        )
        return int(result.get("status", 0))

    def wait_for_active_scan(self, scan_id: str, poll_interval: int = 10) -> None:
        """Block until the active scan reaches 100% completion."""
        if MOCK_ZAP:
            logger.info("Mock: active scan complete immediately")
            return
        logger.info("Waiting for active scan scan_id=%s ...", scan_id)
        while True:
            status = self.get_active_scan_status(scan_id)
            logger.info("Active scan progress: %d%%", status)
            if status >= 100:
                break
            time.sleep(poll_interval)
        logger.info("Active scan complete")

    def get_alerts(self, target_url: str = TARGET_URL) -> list[dict]:
        """Return all alerts found for the target URL."""
        if MOCK_ZAP:
            return [
                {
                    "alertRef": "10016",
                    "alert": "Web Browser XSS Protection Not Enabled",
                    "risk": "Low",
                    "confidence": "Medium",
                    "url": "http://juice-shop:3000/",
                    "description": "Web Browser XSS Protection is not enabled.",
                    "solution": "Ensure that the web browser's XSS filter is enabled.",
                    "cweid": "933",
                    "wascid": "14",
                },
                {
                    "alertRef": "10021",
                    "alert": "X-Content-Type-Options Header Missing",
                    "risk": "Low",
                    "confidence": "Medium",
                    "url": "http://juice-shop:3000/login",
                    "description": "The X-Content-Type-Options header is not set.",
                    "solution": "Ensure that the application sets the X-Content-Type-Options header.",
                    "cweid": "693",
                    "wascid": "15",
                },
                {
                    "alertRef": "40012",
                    "alert": "Cross Site Scripting (Reflected)",
                    "risk": "High",
                    "confidence": "Medium",
                    "url": "http://juice-shop:3000/rest/products/search?q=<script>",
                    "description": "Cross-site Scripting (XSS) via reflected input.",
                    "solution": "Validate and encode all user input before rendering.",
                    "cweid": "79",
                    "wascid": "8",
                },
            ]
        result = self._get(
            "JSON/core/view/alerts/",
            {"baseurl": target_url},
        )
        return result.get("alerts", [])

    def run_full_scan(self, target_url: str = TARGET_URL) -> dict:
        """
        Run a complete spider + active scan and return all findings.

        Returns:
            {
                "urls_found": int,
                "crawl_map": list[str],
                "alerts": list[dict],
                "zap_version": str,
            }
        """
        logger.info("Starting full scan of %s", target_url)

        spider_id = self.start_spider(target_url)
        self.wait_for_spider(spider_id)
        crawl_map = self.get_crawl_map()
        logger.info("Crawl map: %d URLs found", len(crawl_map))

        scan_id = self.start_active_scan(target_url)
        self.wait_for_active_scan(scan_id)
        alerts = self.get_alerts(target_url)
        logger.info("Alerts found: %d", len(alerts))

        return {
            "urls_found": len(crawl_map),
            "crawl_map": crawl_map,
            "alerts": alerts,
            "zap_version": self.get_version(),
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    client = ZAPClient()
    print(f"ZAP version: {client.get_version()}")
    results = client.run_full_scan()
    print(f"URLs found: {results['urls_found']}")
    print(f"Alerts: {len(results['alerts'])}")
    for alert in results["alerts"]:
        print(f"  [{alert['risk']}] {alert['alert']} — {alert['url']}")
