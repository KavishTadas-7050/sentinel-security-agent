"""LangChain-compatible LLM backend.

Reuses the same provider detection pattern as ai-qa-toolbox:
- GEMINI_API_KEY set → uses Google Gemini (free)
- OPENAI_API_KEY set → uses OpenAI
- MOCK_LLM=true → returns mock responses (no API key needed)
"""

from __future__ import annotations

import os
import json
from typing import Any, List, Optional

from langchain_core.language_models.llms import LLM
from langchain_core.callbacks.manager import CallbackManagerForLLMRun


def _detect_provider() -> str:
    explicit = os.getenv("LLM_PROVIDER", "").lower()
    if explicit in ("gemini", "openai"):
        return explicit
    if os.getenv("GEMINI_API_KEY"):
        return "gemini"
    return "openai"


def _build_raw_client():
    from openai import OpenAI
    provider = _detect_provider()
    if provider == "gemini":
        return OpenAI(
            api_key=os.getenv("GEMINI_API_KEY"),
            base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        ), "gemini-2.0-flash"
    return OpenAI(), os.getenv("OPENAI_MODEL", "gpt-4o-mini")


_MOCK_RESPONSE = """{
  "is_false_positive": false,
  "false_positive_reason": null,
  "reachable_in_crawl": true,
  "exploitability": "MEDIUM",
  "adjusted_severity": "MEDIUM",
  "analyst_note": "Mock assessment — no LLM call made."
}"""


def _build_mock_response(prompt: str) -> str:
    alert_name = ""
    alert_url = ""
    crawl_urls = set()

    in_crawl_sample = False
    for line in prompt.splitlines():
        stripped = line.strip()
        if stripped.startswith("Alert name:"):
            alert_name = stripped.removeprefix("Alert name:").strip()
        elif stripped.startswith("URL:"):
            alert_url = stripped.removeprefix("URL:").strip()
        elif stripped.startswith("CRAWL MAP SAMPLE"):
            in_crawl_sample = True
        elif stripped.startswith("ASSESSMENT RULES:"):
            in_crawl_sample = False
        elif in_crawl_sample and stripped.startswith("- "):
            crawl_urls.add(stripped.removeprefix("- ").strip())

    reachable = alert_url in crawl_urls
    alert_name_lower = alert_name.lower()
    url_lower = alert_url.lower()

    is_security_header = "header" in alert_name_lower or "x-frame-options" in alert_name_lower
    is_high_impact = "sql injection" in alert_name_lower or "cross site scripting" in alert_name_lower

    if is_security_header and ("/api/" in url_lower or "/rest/" in url_lower):
        is_false_positive = True
        exploitability = "NEGLIGIBLE"
        adjusted_severity = "INFO"
        reason = "Security header finding on a non-browsable API endpoint in mock mode."
    elif is_high_impact and reachable:
        is_false_positive = False
        exploitability = "HIGH"
        adjusted_severity = "HIGH"
        reason = None
    else:
        is_false_positive = False
        exploitability = "MEDIUM" if reachable else "LOW"
        adjusted_severity = "MEDIUM" if reachable else "LOW"
        reason = None

    return json.dumps({
        "is_false_positive": is_false_positive,
        "false_positive_reason": reason,
        "reachable_in_crawl": reachable,
        "exploitability": exploitability,
        "adjusted_severity": adjusted_severity,
        "analyst_note": "Mock assessment — no LLM call made.",
    })


class SentinelLLM(LLM):
    """LangChain LLM wrapper for Sentinel — supports Gemini, OpenAI, and mock."""

    @property
    def _llm_type(self) -> str:
        return "sentinel"

    def _call(
        self,
        prompt: str,
        stop: Optional[List[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> str:
        if os.getenv("MOCK_LLM") == "true":
            return _build_mock_response(prompt)

        client, model = _build_raw_client()
        provider = _detect_provider()

        if provider == "gemini":
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.choices[0].message.content

        response = client.responses.create(model=model, input=prompt)
        return response.output_text

    @property
    def _identifying_params(self) -> dict:
        return {"llm_type": self._llm_type}


def get_llm() -> SentinelLLM:
    return SentinelLLM()
