from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from analysis.quark import QuarkConfig, QuarkRunner
from analysis.reporting import ReportManager
from analysis.runtime.context import RunContext
from analysis.runtime.clock import now_utc_iso
from analysis.normalize.stage3 import normalize_stage3
from analysis.runtime.fs import ensure_run_dir, ensure_run_json, write_json, write_run_finished
from analysis.stages import STAGE_CROSS_TOOL
from analysis.storage import Storage
from analysis.models.quark import QuarkReport
from models import Run


@dataclass
class Stage3QuarkConfig:
    quark_timeout_sec: int = 120
    quark_rules_dir: str | None = None


class Stage3QuarkRunner:
    def __init__(
        self,
        storage: Storage,
        config: Stage3QuarkConfig | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> None:
        self.storage = storage
        self.config = config or Stage3QuarkConfig()
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
        log_path = run_dir / "logs" / "stage3_quark.txt"
        log = self._build_logger(log_path)
        quark_dir = run_dir / "artifacts" / "quark"
        quark_dir.mkdir(parents=True, exist_ok=True)

        log("Stage3 Quark run started.")
        self._emit("Starting Quark Stage3 analysis...")

        quark_report: QuarkReport | None = None
        try:
            if not apk_path.exists():
                raise RuntimeError(f"APK not found: {apk_path}")
            if apk_path.stat().st_size == 0:
                raise RuntimeError(f"APK is empty: {apk_path}")
            quark_report = self._run_quark(apk_path, quark_dir, run_dir, log, ctx=ctx)
            if quark_report.status != "ok":
                raise RuntimeError(f"Quark analysis status: {quark_report.status}")

            run.status = "Done"
            run.finished_at = datetime.now().isoformat(timespec="seconds")
            report_manager = ReportManager(self.storage)
            _, html_path = report_manager.generate_stage3(run, run_dir, None, quark_report)
            run.report_path = str(html_path)
            log("Stage3 Quark run completed.")
            return run
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"Stage3 Quark run failed: {exc}")
            run.status = "Error"
            run.finished_at = datetime.now().isoformat(timespec="seconds")
            run.errors.append(f"Stage3 Quark failed: {exc}")
            report_manager = ReportManager(self.storage)
            report_manager.generate_stage3(run, run_dir, None, quark_report)
            raise
        finally:
            indicators = normalize_stage3(ctx, None, quark_report)
            write_json(ctx.run_dir / "normalized" / "indicators.json", indicators)
            tools_index = ctx.meta.get("tools_index") or []
            write_run_finished(ctx, now_utc_iso(), tools_index)

    def _run_quark(
        self,
        apk_path: Path,
        quark_dir: Path,
        run_dir: Path,
        log: Callable[[str], None],
        ctx: RunContext | None = None,
    ) -> QuarkReport:
        self._emit("Running Quark rules...")
        rules_dir = Path(self.config.quark_rules_dir) if self.config.quark_rules_dir else None
        quark_config = QuarkConfig(rules_dir=rules_dir, timeout_sec=self.config.quark_timeout_sec)
        runner = QuarkRunner(quark_config, on_progress=log)
        report = runner.run(
            apk_path,
            quark_dir,
            run_dir,
            ctx=ctx,
        )
        if report.status != "ok":
            log(f"Quark analysis status: {report.status}")
        return report


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
