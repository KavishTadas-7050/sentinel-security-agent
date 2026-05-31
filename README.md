# sentinel-security-agent

> LangChain agent that eliminates OWASP ZAP false positives using
> application crawl map reasoning.

## Why AI? (not just automation)

OWASP ZAP reports every reachable vulnerability regardless of whether the
code path is actually exercised in production. This agent cross-references
the crawl map and application telemetry to suppress false positives before
they reach the security report — turning a noisy 200-item ZAP report into
a focused 15-item action list.

## Status

Work in progress — Day 1 scaffold.
