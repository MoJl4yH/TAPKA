import time
import subprocess
from pathlib import Path

from models import CommandResult


def run_command(
    tool: str,
    argv: list[str],
    cwd: str,
    stdout_path: str,
    stderr_path: str,
    timeout: int | None = None,
) -> CommandResult:
    start_time = time.monotonic()
    stdout_file = Path(stdout_path)
    stderr_file = Path(stderr_path)
    stdout_file.parent.mkdir(parents=True, exist_ok=True)
    stderr_file.parent.mkdir(parents=True, exist_ok=True)

    with stdout_file.open("w", encoding="utf-8", errors="replace") as stdout_handle, stderr_file.open(
        "w",
        encoding="utf-8",
        errors="replace",
    ) as stderr_handle:
        try:
            result = subprocess.run(
                argv,
                cwd=cwd,
                stdout=stdout_handle,
                stderr=stderr_handle,
                timeout=timeout,
                text=True,
                check=False,
            )
            duration = time.monotonic() - start_time
            return CommandResult(
                tool=tool,
                argv=argv,
                cwd=cwd,
                return_code=result.returncode,
                duration_sec=duration,
                stdout_path=str(stdout_file),
                stderr_path=str(stderr_file),
            )
        except subprocess.TimeoutExpired:
            duration = time.monotonic() - start_time
            stderr_handle.write("Command timed out.\n")
            return CommandResult(
                tool=tool,
                argv=argv,
                cwd=cwd,
                return_code=None,
                duration_sec=duration,
                stdout_path=str(stdout_file),
                stderr_path=str(stderr_file),
                timed_out=True,
                error="timeout",
            )
        except (OSError, ValueError) as exc:
            duration = time.monotonic() - start_time
            stderr_handle.write(f"Command failed: {exc}\n")
            return CommandResult(
                tool=tool,
                argv=argv,
                cwd=cwd,
                return_code=None,
                duration_sec=duration,
                stdout_path=str(stdout_file),
                stderr_path=str(stderr_file),
                error=str(exc),
            )
