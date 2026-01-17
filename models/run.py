from pydantic import BaseModel, Field

from models.command_result import CommandResult


class Run(BaseModel):
    run_id: str
    project_id: str
    stage: str
    started_at: str
    finished_at: str | None = None
    status: str = "Running"
    apk_path: str
    command_results: list[CommandResult] = Field(default_factory=list)
    findings_path: str | None = None
    report_path: str | None = None
    tools_checked: list[str] = Field(default_factory=list)
    tools_missing: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
