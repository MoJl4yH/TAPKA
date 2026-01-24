from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from analysis.runtime.context import RunContext
from analysis.runtime.hash import sha256_file


def ensure_run_dir(ctx: RunContext) -> None:
    for name in ("env", "tools", "normalized", "report", "artifacts", "logs"):
        (ctx.run_dir / name).mkdir(parents=True, exist_ok=True)


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def tool_dir(ctx: RunContext, tool_name: str) -> Path:
    return ctx.run_dir / "tools" / tool_name


def clear_tool_dir(ctx: RunContext, tool_name: str) -> None:
    path = tool_dir(ctx, tool_name)
    if path.exists() and path.is_dir():
        shutil.rmtree(path)


def ensure_run_json(ctx: RunContext) -> None:
    run_path = ctx.run_dir / "run.json"
    if run_path.exists():
        try:
            data = json.loads(run_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, ValueError):
            data = {}
        if data.get("schema") == "tapka.run.v1":
            return
    write_run_json(ctx)


def write_tool_result_json(ctx: RunContext, tool_name: str, obj: dict[str, Any]) -> None:
    write_json(tool_dir(ctx, tool_name) / "tool_result.json", obj)


def write_tool_bundle(
    ctx: RunContext,
    tool_name: str,
    cmd: list[str],
    started_at: str,
    finished_at: str,
    exit_code: int,
    stdout: str,
    stderr: str,
    artifacts: dict[str, str],
    extra_fields: dict[str, Any] | None = None,
) -> dict[str, str]:
    tool_root = tool_dir(ctx, tool_name)
    tool_root.mkdir(parents=True, exist_ok=True)
    cmd_path = tool_root / "cmd.txt"
    stdout_path = tool_root / "stdout.txt"
    stderr_path = tool_root / "stderr.txt"
    cmd_path.write_text(" ".join(cmd), encoding="utf-8")
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")

    try:
        stdout_rel = str(stdout_path.relative_to(ctx.run_dir))
    except ValueError:
        stdout_rel = str(stdout_path)
    try:
        stderr_rel = str(stderr_path.relative_to(ctx.run_dir))
    except ValueError:
        stderr_rel = str(stderr_path)
    try:
        tool_result_rel = str((tool_root / "tool_result.json").relative_to(ctx.run_dir))
    except ValueError:
        tool_result_rel = str(tool_root / "tool_result.json")

    ok = exit_code == 0

    payload = {
        "schema": "tapka.tool_result.v1",
        "tool": tool_name,
        "ok": ok,
        "exit_code": exit_code,
        "cmd": cmd,
        "started_at": started_at,
        "finished_at": finished_at,
        "stdout_path": stdout_rel,
        "stderr_path": stderr_rel,
        "artifacts": artifacts,
        "data": {},
    }
    if extra_fields:
        payload.update(extra_fields)
    write_json(tool_root / "tool_result.json", payload)
    return {"tool": tool_name, "tool_result": tool_result_rel}


def write_run_json(ctx: RunContext) -> None:
    payload = {
        "schema": "tapka.run.v1",
        "stage": ctx.stage,
        "run_id": ctx.run_id,
        "started_at": ctx.started_at,
        "input": {
            "apk_path": str(ctx.apk_path),
            "sha256": sha256_file(ctx.apk_path),
        },
    }
    write_json(ctx.run_dir / "run.json", payload)


def write_run_finished(ctx: RunContext, finished_at: str, tools_index: list[dict[str, Any]]) -> None:
    run_path = ctx.run_dir / "run.json"
    data: dict[str, Any] = {}
    if run_path.exists():
        try:
            data = json.loads(run_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, ValueError):
            data = {}
    data["finished_at"] = finished_at
    data["tools"] = tools_index
    write_json(run_path, data)
