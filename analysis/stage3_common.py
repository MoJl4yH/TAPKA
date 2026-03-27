from __future__ import annotations

import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from analysis.runtime.clock import now_utc_iso


def find_tool(name: str) -> str:
    """Resolve a CLI tool name to its full path.

    Search order:
    1. System PATH (shutil.which)
    2. Directory of the current Python interpreter (venv bin)
    3. Return bare name as fallback (subprocess will raise its own error)
    """
    found = shutil.which(name)
    if found:
        return found
    venv_candidate = Path(sys.executable).parent / name
    if venv_candidate.is_file():
        return str(venv_candidate)
    return name
from analysis.runtime.context import RunContext
from analysis.runtime.fs import ensure_run_dir, ensure_run_json, write_json, write_run_finished
from analysis.stages import STAGE_CROSS_TOOL
from analysis.storage import Storage
from models import Run


def prepare_stage3_run(
    storage: Storage,
    project_id: str,
    ctx: RunContext | None,
) -> tuple[RunContext, Path, Path, Run]:
    if ctx is None:
        ctx = storage.get_or_create_stage3_run(project_id)
    run_dir = ctx.run_dir
    apk_path = Path(ctx.apk_path)
    run = Run(
        run_id=ctx.run_id,
        project_id=project_id,
        stage=STAGE_CROSS_TOOL,
        started_at=ctx.started_at,
        apk_path=str(apk_path),
    )
    ensure_run_dir(ctx)
    ensure_run_json(ctx)
    return ctx, run_dir, apk_path, run


def ensure_apk_ready(apk_path: Path) -> None:
    if not apk_path.exists():
        raise RuntimeError(f"APK не найден: {apk_path}")
    if apk_path.stat().st_size == 0:
        raise RuntimeError(f"APK пуст: {apk_path}")


def build_stage3_logger(
    path: Path,
    on_progress: Callable[[str], None] | None,
) -> Callable[[str], None]:
    def _log(message: str) -> None:
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        if on_progress:
            on_progress(line)

    return _log


def emit_progress(on_progress: Callable[[str], None] | None, message: str) -> None:
    if on_progress:
        on_progress(message)


def append_run_error(run: Run, message: str) -> None:
    errors = run.errors if isinstance(run.errors, list) else []
    errors = [str(item) for item in errors]
    errors.append(message)
    run.errors = errors


def resolve_tool_result_path(run_dir: Path, tool_index: dict[str, str], tool_name: str) -> Path:
    rel_path = tool_index.get("tool_result")
    if rel_path:
        return run_dir / rel_path
    return run_dir / "tools" / tool_name / "tool_result.json"


def read_tool_ok(path: Path) -> tuple[bool, int | None]:
    if not path.exists():
        return False, None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, ValueError):
        return False, None
    ok = payload.get("ok")
    exit_code = payload.get("exit_code")
    if isinstance(ok, bool):
        return ok, exit_code if isinstance(exit_code, int) else None
    if isinstance(exit_code, int):
        return exit_code == 0, exit_code
    return False, None


def finalize_stage3_run(ctx: RunContext, indicators: dict) -> None:
    write_json(ctx.run_dir / "normalized" / "indicators.json", indicators)
    tools_index = ctx.meta.get("tools_index") or []
    write_run_finished(ctx, now_utc_iso(), tools_index)
