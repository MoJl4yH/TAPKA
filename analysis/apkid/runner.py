from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from analysis.runtime.clock import now_utc_iso
from analysis.runtime.context import RunContext
from analysis.runtime.exec import run_command_capture
from analysis.runtime.fs import clear_tool_dir, tool_dir, write_text, write_tool_bundle


APKID_COMMAND = "apkid"


@dataclass
class ApkidConfig:
    timeout_sec: int | None = 120
    scan_depth: int | None = None
    entry_max_scan_size: int | None = None
    typing: str | None = None
    include_types: bool = False


class ApkidRunner:
    def __init__(
        self,
        config: ApkidConfig | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> None:
        self.config = config or ApkidConfig()
        self.on_progress = on_progress

    def run(self, ctx: RunContext, apk_path: Path | None = None) -> dict[str, str]:
        tool_started_at = now_utc_iso()
        cmd = self._build_cmd(apk_path or ctx.apk_path)
        stdout = ""
        stderr = ""
        exit_code = 0
        json_ok = False
        clear_tool_dir(ctx, "apkid")
        if shutil.which(APKID_COMMAND) is None:
            exit_code = 127
            stderr = "apkid executable not found in PATH."
        else:
            try:
                exit_code, stdout, stderr = run_command_capture(
                    cmd,
                    timeout=self.config.timeout_sec,
                )
            except subprocess.TimeoutExpired as exc:
                stdout = exc.output or ""
                stderr = exc.stderr or ""
                if stderr:
                    stderr = stderr.rstrip("\n") + "\n"
                stderr += f"Timeout after {self.config.timeout_sec}s"
                exit_code = 1
            except Exception as exc:  # pylint: disable=broad-exception-caught
                stderr = str(exc)
                exit_code = 1

        if stdout:
            try:
                json.loads(stdout)
                json_ok = True
            except (json.JSONDecodeError, TypeError, ValueError):
                json_ok = False

        tool_root = tool_dir(ctx, "apkid")
        raw_path = tool_root / "raw" / "apkid.json"
        write_text(raw_path, stdout)

        artifacts: dict[str, str] = {}
        if raw_path.exists():
            try:
                artifacts["raw_json"] = str(raw_path.relative_to(ctx.run_dir))
            except ValueError:
                artifacts["raw_json"] = str(raw_path)

        tool_finished_at = now_utc_iso()
        ok = exit_code == 0 and json_ok
        tool_index = write_tool_bundle(
            ctx,
            "apkid",
            cmd,
            tool_started_at,
            tool_finished_at,
            exit_code,
            stdout or "",
            stderr or "",
            artifacts,
            extra_fields={"ok": ok},
        )
        tools_index = ctx.meta.setdefault("tools_index", [])
        tools_index[:] = [entry for entry in tools_index if entry.get("tool") != "apkid"]
        tools_index.append(tool_index)
        return tool_index

    def _build_cmd(self, apk_path: Path) -> list[str]:
        cmd = [APKID_COMMAND, str(apk_path), "-j"]
        if self.config.timeout_sec is not None:
            cmd.extend(["--timeout", str(self.config.timeout_sec)])
        if self.config.scan_depth is not None:
            cmd.extend(["--scan-depth", str(self.config.scan_depth)])
        if self.config.entry_max_scan_size is not None:
            cmd.extend(["--entry-max-scan-size", str(self.config.entry_max_scan_size)])
        if self.config.typing is not None:
            cmd.extend(["--typing", str(self.config.typing)])
        if self.config.include_types:
            cmd.append("--include-types")
        return cmd
