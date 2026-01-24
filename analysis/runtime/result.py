from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ToolExecution:
    tool: str
    ok: bool
    exit_code: int
    cmd: list[str]
    started_at: str
    finished_at: str
    stdout_relpath: str
    stderr_relpath: str
    tool_result_relpath: str
    artifacts: dict[str, str]
