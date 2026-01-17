from pydantic import BaseModel


class CommandResult(BaseModel):
    tool: str
    argv: list[str]
    cwd: str
    return_code: int | None
    duration_sec: float
    stdout_path: str
    stderr_path: str
    status: str | None = None
    timed_out: bool = False
    error: str | None = None
