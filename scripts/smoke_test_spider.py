"""Spider smoke test — confirms ZAP + Juice Shop networking works.

Run after docker compose up:
    python scripts/smoke_test_spider.py

Asserts:
- ZAP version endpoint returns 200 OK
- Spider finds at least 10 URLs on the target
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()

from agent.zap_wrapper import ZAPClient  # noqa: E402


def main() -> None:
    client = ZAPClient()

    print("=== Sentinel Spider Smoke Test ===\n")

    # Test 1: ZAP version
    print("[1/2] Checking ZAP version endpoint...")
    version = client.get_version()
    print(f"      ZAP version: {version}")
    assert version != "unknown", "ZAP version endpoint failed"
    print("      PASS\n")

    # Test 2: Spider finds URLs
    target = os.getenv("TARGET_URL", "http://juice-shop:3000")
    print(f"[2/2] Spidering {target} ...")
    scan_id = client.start_spider(target)
    client.wait_for_spider(scan_id)
    urls = client.get_crawl_map()
    print(f"      URLs found: {len(urls)}")
    for url in urls[:5]:
        print(f"      - {url}")
    if len(urls) > 5:
        print(f"      ... and {len(urls) - 5} more")
    assert len(urls) >= 10, f"Expected 10+ URLs, got {len(urls)}"
    print("      PASS\n")

    print("=== All smoke tests passed ===")


if __name__ == "__main__":
    main()
