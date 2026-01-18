from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from models.finding import Finding
from analysis.models.mobsf import MobSFReport

ReportStatus = Literal["ok", "partial", "fail", "not_implemented"]


class ProjectInfo(BaseModel):
    project_id: str
    apk_name: str | None = None
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    apk_sha256: str | None = None
    apk_size: int | None = None
    apk_path: str | None = None


class RunInfo(BaseModel):
    run_id: str
    stage: str
    status: str
    started_at: str
    finished_at: str | None = None
    duration_sec: float | None = None
    run_dir: str | None = None


class ToolStatus(BaseModel):
    tool: str
    status: ReportStatus
    details: str | None = None
    error_count: int | None = None
    matches: int | None = None
    rules: int | None = None


class BaseReportModel(BaseModel):
    report_type: str
    generated_at: str
    project: ProjectInfo
    run: RunInfo
    tool_statuses: list[ToolStatus] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    status: ReportStatus = "ok"
    notes: list[str] = Field(default_factory=list)


class Stage1ReportModel(BaseReportModel):
    manifest_permissions: list[str] = Field(default_factory=list)
    manifest_exported: list[str] = Field(default_factory=list)
    manifest_flags: list[str] = Field(default_factory=list)
    endpoints_summary: dict[str, int] = Field(default_factory=dict)
    signing_summary: dict[str, int] = Field(default_factory=dict)


class Stage2ReportModel(BaseReportModel):
    status: ReportStatus = "not_implemented"


class Stage3ReportModel(BaseReportModel):
    mobsf: MobSFReport | None = None
    status: ReportStatus = "not_implemented"


class OverallReportModel(BaseReportModel):
    status: ReportStatus = "not_implemented"
