from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from analysis.apkid.runner import ApkidConfig, ApkidRunner
from analysis.normalize.stage3 import normalize_stage3
from analysis.reporting import ReportManager
from analysis.runtime.context import RunContext
from analysis.stage3_common import (
    append_run_error,
    build_stage3_logger,
    emit_progress,
    ensure_apk_ready,
    finalize_stage3_run,
    prepare_stage3_run,
    read_tool_ok,
    resolve_tool_result_path,
)
from analysis.storage import Storage
from models import Run


@dataclass
class Stage3ApkidConfig:
    apkid_timeout_sec: int | None = 120
    apkid_scan_depth: int | None = None
    apkid_entry_max_scan_size: int | None = None
    apkid_typing: str | None = None
    apkid_include_types: bool = False


class Stage3ApkidRunner:
    def __init__(
        self,
        storage: Storage,
        config: Stage3ApkidConfig | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> None:
        self.storage = storage
        self.config = config or Stage3ApkidConfig()
        self.on_progress = on_progress

    def run(self, project_id: str, ctx: RunContext | None = None) -> Run:
        ctx, run_dir, apk_path, run = prepare_stage3_run(self.storage, project_id, ctx)
        log = build_stage3_logger(run_dir / "logs" / "stage3_apkid.txt", self.on_progress)

        log("Stage3 APKiD run started.")
        emit_progress(self.on_progress, "Starting APKiD Stage3 analysis...")
        try:
            ensure_apk_ready(apk_path)
            config = ApkidConfig(
                timeout_sec=self.config.apkid_timeout_sec,
                scan_depth=self.config.apkid_scan_depth,
                entry_max_scan_size=self.config.apkid_entry_max_scan_size,
                typing=self.config.apkid_typing,
                include_types=self.config.apkid_include_types,
            )
            runner = ApkidRunner(config=config, on_progress=log)
            tool_index = runner.run(ctx, apk_path)
            tool_result_path = resolve_tool_result_path(run_dir, tool_index, "apkid")
            tool_ok, exit_code = read_tool_ok(tool_result_path)
            if not tool_ok:
                suffix = f" (exit_code={exit_code})" if exit_code is not None else ""
                raise RuntimeError(f"APKiD analysis failed{suffix}.")

            run.status = "Done"
            run.finished_at = datetime.now().isoformat(timespec="seconds")
            report_manager = ReportManager(self.storage)
            _, html_path = report_manager.generate_stage3(run, run_dir, None, None)
            run.report_path = str(html_path)
            log("Stage3 APKiD run completed.")
            return run
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"Stage3 APKiD run failed: {exc}")
            run.status = "Error"
            run.finished_at = datetime.now().isoformat(timespec="seconds")
            append_run_error(run, f"Stage3 APKiD failed: {exc}")
            report_manager = ReportManager(self.storage)
            report_manager.generate_stage3(run, run_dir, None, None)
            raise
        finally:
            indicators = normalize_stage3(ctx, None, None)
            finalize_stage3_run(ctx, indicators)
