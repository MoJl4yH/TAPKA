from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


ReportStatusV2 = Literal["ok", "partial", "fail", "not_implemented"]
ToolStatusV2 = Literal["ok", "partial", "fail", "skipped"]
SeverityHintV2 = Literal["info", "low", "medium", "high"]
ConfidenceV2 = Literal["C1", "C2", "C3"]
ArtifactKindV2 = Literal["file", "dir"]
SectionKindV2 = Literal["json_ref", "table", "list", "text"]


class ProjectInfoV2(BaseModel):
    project_id: str
    apk_name: str | None = None
    apk_path: str | None = None
    apk_sha256: str | None = None
    apk_size: int | None = None
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None


class RunInfoV2(BaseModel):
    run_id: str
    stage: str
    status: ReportStatusV2
    started_at: str | None = None
    finished_at: str | None = None
    duration_sec: float | None = None
    run_dir: str | None = None


class SourceRefV2(BaseModel):
    stage: str
    tool: str
    ref: str | None = None
    rule: str | None = None


class EvidenceItemV2(BaseModel):
    kind: str
    file: str | None = None
    line: int | None = None
    snippet: str | None = None
    ref: str | None = None


class ArtifactRefV2(BaseModel):
    id: str
    kind: ArtifactKindV2
    name: str
    path: str
    sha256: str | None = None
    size: int | None = None
    mime: str | None = None


class ToolRunV2(BaseModel):
    tool: str
    status: ToolStatusV2
    version: str | None = None
    cmd: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    duration_ms: int | None = None
    outputs: dict[str, str] = Field(default_factory=dict)
    metrics: dict[str, int | float | str | bool] = Field(default_factory=dict)
    details: str | None = None


class IndicatorExampleV2(BaseModel):
    file: str | None = None
    line: int | None = None
    snippet: str | None = None


class IndicatorV2(BaseModel):
    id: str
    type: str
    value: str
    severity_hint: SeverityHintV2 = "info"
    noise: bool = False
    tags: list[str] = Field(default_factory=list)
    sources: list[SourceRefV2] = Field(default_factory=list)
    examples: list[IndicatorExampleV2] = Field(default_factory=list)


class FindingV2(BaseModel):
    id: str
    category: str
    title: str
    severity: SeverityHintV2
    confidence: ConfidenceV2 = "C1"
    tags: list[str] = Field(default_factory=list)
    description: str = ""
    recommendation: str = ""
    evidence: list[EvidenceItemV2] = Field(default_factory=list)
    sources: list[SourceRefV2] = Field(default_factory=list)
    related_indicators: list[str] = Field(default_factory=list)


class SectionV2(BaseModel):
    id: str
    title: str
    kind: SectionKindV2
    summary: str = ""
    ref: str | None = None
    data: Any | None = None


class ReportV2(BaseModel):
    schema_version: str = Field(default="tapka.report.v2", alias="schema")
    report_type: str = "stage"
    stage: str
    generated_at: str
    project: ProjectInfoV2
    run: RunInfoV2
    tools: list[ToolRunV2] = Field(default_factory=list)
    artifacts: list[ArtifactRefV2] = Field(default_factory=list)
    indicators: list[IndicatorV2] = Field(default_factory=list)
    findings: list[FindingV2] = Field(default_factory=list)
    sections: list[SectionV2] = Field(default_factory=list)
    status: ReportStatusV2 = "ok"
    notes: list[str] = Field(default_factory=list)
