from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from analysis.apkid.runner import ApkidConfig, ApkidRunner
from analysis.normalize.stage3 import normalize_stage3
from analysis.reporting import ReportManager
from analysis.runtime.clock import now_utc_iso
from analysis.runtime.context import RunContext
from analysis.runtime.fs import ensure_run_dir, ensure_run_json, write_json, write_run_finished
from analysis.stages import STAGE_CROSS_TOOL
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
        if ctx is None:
            ctx = self.storage.get_or_create_stage3_run(project_id)
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
        log_path = run_dir / "logs" / "stage3_apkid.txt"
        log = self._build_logger(log_path)

        log("Stage3 APKiD run started.")
        self._emit("Starting APKiD Stage3 analysis...")
        try:
            if not apk_path.exists():
                raise RuntimeError(f"APK not found: {apk_path}")
            if apk_path.stat().st_size == 0:
                raise RuntimeError(f"APK is empty: {apk_path}")
            config = ApkidConfig(
                timeout_sec=self.config.apkid_timeout_sec,
                scan_depth=self.config.apkid_scan_depth,
                entry_max_scan_size=self.config.apkid_entry_max_scan_size,
                typing=self.config.apkid_typing,
                include_types=self.config.apkid_include_types,
            )
            runner = ApkidRunner(config=config, on_progress=log)
            runner.run(ctx, apk_path)

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
            run.errors.append(f"Stage3 APKiD failed: {exc}")
            report_manager = ReportManager(self.storage)
            report_manager.generate_stage3(run, run_dir, None, None)
            raise
        finally:
            indicators = normalize_stage3(ctx, None, None)
            write_json(ctx.run_dir / "normalized" / "indicators.json", indicators)
            tools_index = ctx.meta.get("tools_index") or []
            write_run_finished(ctx, now_utc_iso(), tools_index)

    def _build_logger(self, path: Path) -> Callable[[str], None]:
        def _log(message: str) -> None:
            timestamp = datetime.now().strftime("%H:%M:%S")
            line = f"[{timestamp}] {message}"
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            if self.on_progress:
                self.on_progress(line)

        return _log

    def _emit(self, message: str) -> None:
        if self.on_progress:
            self.on_progress(message)
