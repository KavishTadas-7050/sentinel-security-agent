"""Prompt templates and Pydantic schemas for vulnerability assessment."""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import JsonOutputParser


class VulnAssessment(BaseModel):
    """Structured vulnerability assessment output."""

    is_false_positive: bool = Field(
        description="True if this alert is a false positive that should be suppressed"
    )
    false_positive_reason: Optional[str] = Field(
        default=None,
        description="Explanation of why this is a false positive, or null if it is not"
    )
    reachable_in_crawl: bool = Field(
        description="True if the affected URL appears in the spider crawl map"
    )
    exploitability: str = Field(
        description="One of: HIGH, MEDIUM, LOW, NEGLIGIBLE"
    )
    adjusted_severity: str = Field(
        description="One of: CRITICAL, HIGH, MEDIUM, LOW, INFO"
    )
    analyst_note: str = Field(
        description="One sentence summary for the security analyst"
    )


parser = JsonOutputParser(pydantic_object=VulnAssessment)

VULN_CLASSIFY_PROMPT = PromptTemplate(
    template="""You are a senior application security engineer performing a ZAP scan triage.
{format_instructions}

You must assess whether this ZAP alert is a true positive or false positive,
considering whether the affected URL is reachable in the application crawl map.

ALERT DETAILS:
  Alert name:   {alert_name}
  Risk level:   {risk}
  Confidence:   {confidence}
  URL:          {url}
  Description:  {description}
  Solution:     {solution}
  CWE ID:       {cweid}

CRAWL MAP SAMPLE (URLs discovered by spider — {crawl_count} total):
{crawl_sample}

ASSESSMENT RULES:
- If the URL is NOT in the crawl map, set reachable_in_crawl=false
- Security headers on non-HTML API endpoints are often false positives
- SQL injection and XSS on login/search forms that appear in the crawl are HIGH priority
- Admin panel URLs not in the crawl map should have reachable_in_crawl=false
- Adjust severity DOWN one level if confidence is Low
- Adjust severity DOWN one level if endpoint is non-browsable (REST API, health check)

Respond ONLY with valid JSON matching the schema. No markdown, no code fences.""",
    input_variables=[
        "alert_name", "risk", "confidence", "url",
        "description", "solution", "cweid",
        "crawl_count", "crawl_sample",
    ],
    partial_variables={"format_instructions": parser.get_format_instructions()},
)
