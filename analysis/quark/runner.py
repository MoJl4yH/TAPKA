from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from analysis.runtime.clock import now_utc_iso
from analysis.runtime.context import RunContext
from analysis.runtime.exec import run_command_capture
from analysis.runtime.fs import clear_tool_dir, write_tool_bundle
from analysis.settings import SETTINGS_DIR
from analysis.models.quark import QuarkReport, QuarkSummary


DEFAULT_RULES_DIR = SETTINGS_DIR / "quark-rules"
DEFAULT_SOURCE_RULES_DIR = Path.home() / ".quark-engine" / "quark-rules"
QUARK_COMMAND = "quark"


@dataclass
class QuarkConfig:
    rules_dir: Path | None = None
    timeout_sec: int = 120


class QuarkRunner:
    def __init__(
        self,
        config: QuarkConfig | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> None:
        self.config = config or QuarkConfig()
        self.on_progress = on_progress

    def run(
        self,
        apk_path: Path,
        out_dir: Path,
        run_dir: Path,
        ctx: RunContext | None = None,
    ) -> QuarkReport:
        report = QuarkReport(status="skipped")
        if shutil.which(QUARK_COMMAND) is None:
            report.status = "missing"
            report.errors.append("quark executable not found in PATH.")
            return report

        if ctx is not None:
            clear_tool_dir(ctx, "quark")
            clear_tool_dir(ctx, "quark_retry")

        rules_dir = self._ensure_rules_dir()
        if not rules_dir:
            report.status = "missing_rules"
            report.errors.append("Quark rules directory not found.")
            return report

        rules_path = rules_dir / "rules"
        if not rules_path.is_dir():
            rules_path = rules_dir
        report.rules_dir = str(rules_path)

        out_dir.mkdir(parents=True, exist_ok=True)
        rules_dir_rel = self._relpath(run_dir, rules_path) + "/"
        report.summary.artifacts["rules_dir"] = rules_dir_rel

        def _execute(command: list[str], tool_name: str, timeout_sec: float | None) -> tuple[str, str, int]:
            stdout_handle = None
            stderr_handle = None
            stdout_cb = None
            stderr_cb = None
            if ctx is not None:
                tool_root = ctx.run_dir / "tools" / tool_name
                tool_root.mkdir(parents=True, exist_ok=True)
                stdout_path = tool_root / "stdout.txt"
                stderr_path = tool_root / "stderr.txt"
                stdout_handle = stdout_path.open("w", encoding="utf-8")
                stderr_handle = stderr_path.open("w", encoding="utf-8")

                def _stdout_cb(line: str) -> None:
                    stdout_handle.write(line + "\n")
                    stdout_handle.flush()
                    if self.on_progress:
                        self.on_progress(line)

                def _stderr_cb(line: str) -> None:
                    stderr_handle.write(line + "\n")
                    stderr_handle.flush()
                    if self.on_progress:
                        self.on_progress(line)

                stdout_cb = _stdout_cb
                stderr_cb = _stderr_cb
            else:
                stdout_cb = self._emit
                stderr_cb = self._emit
            try:
                stdout, stderr, return_code = self._run_rule(
                    command,
                    stdout_cb=stdout_cb,
                    stderr_cb=stderr_cb,
                    timeout_sec=timeout_sec,
                )
            except subprocess.TimeoutExpired as exc:
                stdout = self._safe_text(getattr(exc, "stdout", None) or getattr(exc, "output", None))
                stderr = self._safe_text(getattr(exc, "stderr", None))
                if stderr:
                    stderr = stderr.rstrip("\n") + "\n"
                if timeout_sec is not None:
                    stderr += f"Timeout after {timeout_sec}s"
                else:
                    stderr += "Timeout"
                return_code = 1
            finally:
                if stdout_handle:
                    stdout_handle.close()
                if stderr_handle:
                    stderr_handle.close()
            return stdout, stderr, return_code

        output_json_path = out_dir / "quark_output.json"
        base_cmd = [
            QUARK_COMMAND,
            "-r",
            str(rules_path),
            "-a",
            str(apk_path),
            "-s",
            "--output",
            str(output_json_path),
        ]
        cmd = list(base_cmd)

        output_text_path = out_dir / "quark_output.txt"
        self._emit("Running Quark rules directory...")
        tool_started_at = now_utc_iso() if ctx is not None else None
        stdout, stderr, return_code = _execute(cmd, "quark", self.config.timeout_sec)
        tool_finished_at = now_utc_iso() if ctx is not None else None
        output_text = (stdout or "") + ("\n" + stderr if stderr else "")
        output_text_path.write_text(output_text, encoding="utf-8")
        if stdout and not output_json_path.exists():
            try:
                json.loads(stdout)
                output_json_path.write_text(stdout, encoding="utf-8")
            except (json.JSONDecodeError, OSError, ValueError):
                pass
        output_json_artifact = None
        if ctx is not None and output_json_path.exists():
            tool_output_json = ctx.run_dir / "tools" / "quark" / "quark_output.json"
            tool_output_json.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(output_json_path, tool_output_json)
                output_json_artifact = self._relpath(ctx.run_dir, tool_output_json)
            except OSError:
                output_json_artifact = self._relpath(ctx.run_dir, output_json_path)

        if return_code == 0:
            report.status = "ok"
        else:
            report.status = "fail"
            reason = f"quark exited with code {return_code}"
            stderr_first = (stderr or "").strip().splitlines()
            if stderr_first:
                reason = f"{reason}: {stderr_first[0]}"
            report.errors.append(reason)
        report.summary = QuarkSummary(
            rules_total=0,
            rules_matched=0,
            rules_failed=0,
            rules_skipped=0,
            matches=[],
            artifacts={
                "outputs_dir": self._relpath(run_dir, out_dir) + "/",
                **(
                    {"output_json": self._relpath(run_dir, output_json_path)}
                    if output_json_path.exists()
                    else {}
                ),
            },
        )
        primary_index = None
        if ctx is not None and tool_started_at is not None and tool_finished_at is not None:
            artifacts: dict[str, str] = {}
            if out_dir.exists():
                artifacts["outputs_dir"] = self._relpath(ctx.run_dir, out_dir) + "/"
            if output_json_artifact:
                artifacts["output_json"] = output_json_artifact
            primary_index = write_tool_bundle(
                ctx,
                "quark",
                cmd,
                tool_started_at,
                tool_finished_at,
                return_code,
                stdout or "",
                stderr or "",
                artifacts,
            )

        if ctx is not None:
            tools_index = ctx.meta.setdefault("tools_index", [])
            tools_index[:] = [
                entry for entry in tools_index if entry.get("tool") not in ("quark", "quark_retry")
            ]
            if primary_index:
                tools_index.append(primary_index)
        return report

    def _ensure_rules_dir(self) -> Path | None:
        target = self.config.rules_dir or DEFAULT_RULES_DIR
        if target.exists():
            return target
        if DEFAULT_SOURCE_RULES_DIR.exists():
            SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
            shutil.move(str(DEFAULT_SOURCE_RULES_DIR), str(target))
            return target
        return None

    def _run_rule(
        self,
        cmd: list[str],
        stdout_cb: Callable[[str], None] | None = None,
        stderr_cb: Callable[[str], None] | None = None,
        timeout_sec: float | None = None,
    ) -> tuple[str, str, int]:
        env = os.environ.copy()
        env.setdefault("PYTHONUNBUFFERED", "1")
        exit_code, stdout, stderr = run_command_capture(
            cmd,
            env=env,
            timeout=timeout_sec,
            stdout_cb=stdout_cb,
            stderr_cb=stderr_cb,
        )
        return stdout or "", stderr or "", exit_code

    def _safe_text(self, value: str | bytes | bytearray | memoryview | None) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, memoryview):
            value = value.tobytes()
        if isinstance(value, (bytes, bytearray)):
            return bytes(value).decode("utf-8", errors="replace")
        return str(value)

    def _emit(self, message: str) -> None:
        if self.on_progress:
            self.on_progress(message)

    def _safe_name(self, value: str) -> str:
        return "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in value).strip("_")

    def _relpath(self, run_dir: Path, path: Path) -> str:
        try:
            return str(path.relative_to(run_dir))
        except ValueError:
            return str(path)
