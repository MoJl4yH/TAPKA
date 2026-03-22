from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from analysis.runtime.clock import now_utc_iso
from analysis.runtime.context import RunContext
from analysis.runtime.exec import run_command_capture
from analysis.runtime.fs import clear_tool_dir, tool_dir, write_text, write_tool_bundle
from analysis.stage3_common import find_tool


APKLEAKS_COMMAND = find_tool("apkleaks")


@dataclass
class ApkleaksConfig:
    timeout_sec: int | None = 120
    patterns_json: Path | None = None
    args_string: str | None = None


class ApkleaksRunner:
    def __init__(
        self,
        config: ApkleaksConfig | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> None:
        self.config = config or ApkleaksConfig()
        self.on_progress = on_progress

    def run(self, ctx: RunContext, apk_path: Path | None = None) -> dict[str, str]:
        tool_started_at = now_utc_iso()
        clear_tool_dir(ctx, "apkleaks")
        tool_root = tool_dir(ctx, "apkleaks")
        output_path = tool_root / "raw" / "apkleaks.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = self._build_cmd(apk_path or ctx.apk_path, output_path)
        stdout = ""
        stderr = ""
        exit_code = 0
        if shutil.which(APKLEAKS_COMMAND) is None:
            exit_code = 127
            stderr = "apkleaks executable not found in PATH."
        else:
            try:
                stdout_lines: list[str] = []
                stderr_lines: list[str] = []

                def _stdout_cb(line: str) -> None:
                    clean = self._strip_ansi(line)
                    stdout_lines.append(clean + "\n")
                    if self.on_progress:
                        self.on_progress(clean)

                def _stderr_cb(line: str) -> None:
                    clean = self._strip_ansi(line)
                    stderr_lines.append(clean + "\n")
                    if self.on_progress:
                        self.on_progress(clean)

                env = os.environ.copy()
                env["PYTHONUNBUFFERED"] = "1"
                exit_code, stdout, stderr = run_command_capture(
                    cmd,
                    env=env,
                    timeout=self.config.timeout_sec,
                    stdout_cb=_stdout_cb,
                    stderr_cb=_stderr_cb,
                )
                if stdout_lines:
                    stdout = "".join(stdout_lines)
                else:
                    stdout = self._strip_ansi(stdout or "")
                if stderr_lines:
                    stderr = "".join(stderr_lines)
                else:
                    stderr = self._strip_ansi(stderr or "")
            except subprocess.TimeoutExpired as exc:
                stdout = self._strip_ansi(exc.output or "")
                stderr = self._strip_ansi(exc.stderr or "")
                if stderr:
                    stderr = stderr.rstrip("\n") + "\n"
                stderr += f"Timeout after {self.config.timeout_sec}s"
                exit_code = 1
            except Exception as exc:  # pylint: disable=broad-exception-caught
                stderr = str(exc)
                exit_code = 1

        raw_path = output_path
        if not raw_path.exists():
            write_text(raw_path, stdout)

        artifacts: dict[str, str] = {}
        if raw_path.exists():
            try:
                artifacts["raw_json"] = str(raw_path.relative_to(ctx.run_dir))
            except ValueError:
                artifacts["raw_json"] = str(raw_path)

        tool_finished_at = now_utc_iso()
        tool_index = write_tool_bundle(
            ctx,
            "apkleaks",
            cmd,
            tool_started_at,
            tool_finished_at,
            exit_code,
            stdout or "",
            stderr or "",
            artifacts,
        )
        tools_index = ctx.meta.setdefault("tools_index", [])
        tools_index[:] = [entry for entry in tools_index if entry.get("tool") != "apkleaks"]
        tools_index.append(tool_index)
        if self.on_progress:
            self.on_progress("APKLeaks run completed.")
        return tool_index

    def _build_cmd(self, apk_path: Path, output_path: Path) -> list[str]:
        cmd = [APKLEAKS_COMMAND, "-f", str(apk_path), "--json", "--output", str(output_path)]
        if self.config.patterns_json is not None:
            cmd.extend(["-p", str(self.config.patterns_json)])
        if self.config.args_string is not None:
            cmd.extend(["-a", self.config.args_string])
        return cmd

    def _strip_ansi(self, text: str) -> str:
        return re.sub(r"\x1b\[[0-9;]*[mK]", "", text)
