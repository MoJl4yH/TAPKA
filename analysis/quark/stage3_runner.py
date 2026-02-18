from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from analysis.quark import QuarkConfig, QuarkRunner
from analysis.reporting import ReportManager
from analysis.normalize.stage3 import normalize_stage3
from analysis.runtime.context import RunContext
from analysis.stage3_common import (
    append_run_error,
    build_stage3_logger,
    emit_progress,
    ensure_apk_ready,
    finalize_stage3_run,
    prepare_stage3_run,
)
from analysis.storage import Storage
from analysis.models.quark import QuarkReport
from models import Run


@dataclass
class Stage3QuarkConfig:
    quark_timeout_sec: int = 600
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
        ctx, run_dir, apk_path, run = prepare_stage3_run(self.storage, project_id, ctx)
        log = build_stage3_logger(run_dir / "logs" / "stage3_quark.txt", self.on_progress)
        quark_dir = run_dir / "artifacts" / "quark"
        quark_dir.mkdir(parents=True, exist_ok=True)

        log("Stage3 Quark run started.")
        emit_progress(self.on_progress, "Starting Quark Stage3 analysis...")

        quark_report: QuarkReport | None = None
        try:
            ensure_apk_ready(apk_path)
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
            append_run_error(run, f"Stage3 Quark failed: {exc}")
            report_manager = ReportManager(self.storage)
            report_manager.generate_stage3(run, run_dir, None, quark_report)
            raise
        finally:
            indicators = normalize_stage3(ctx, None, quark_report)
            finalize_stage3_run(ctx, indicators)

    def _run_quark(
        self,
        apk_path: Path,
        quark_dir: Path,
        run_dir: Path,
        log: Callable[[str], None],
        ctx: RunContext | None = None,
    ) -> QuarkReport:
        emit_progress(self.on_progress, "Running Quark rules...")
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
