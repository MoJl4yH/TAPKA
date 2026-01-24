from __future__ import annotations

from pydantic import BaseModel, Field


class QuarkRuleResult(BaseModel):
    rule_name: str
    rule_path: str
    matched: bool
    output_path: str | None = None
    error: str | None = None


class QuarkSummary(BaseModel):
    rules_total: int = 0
    rules_matched: int = 0
    rules_failed: int = 0
    rules_skipped: int = 0
    matches: list[QuarkRuleResult] = Field(default_factory=list)
    artifacts: dict[str, str] = Field(default_factory=dict)


class QuarkReport(BaseModel):
    rules_dir: str | None = None
    status: str = "skipped"
    summary: QuarkSummary = Field(default_factory=QuarkSummary)
    errors: list[str] = Field(default_factory=list)
