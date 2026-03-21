from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from analysis.apkleaks.runner import ApkleaksConfig, ApkleaksRunner
from analysis.runtime.clock import now_utc_iso
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
class Stage3ApkleaksConfig:
    apkleaks_timeout_sec: int | None = None
    apkleaks_patterns_json: str | None = None
    apkleaks_args_string: str | None = None


class Stage3ApkleaksRunner:
    def __init__(
        self,
        storage: Storage,
        config: Stage3ApkleaksConfig | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> None:
        self.storage = storage
        self.config = config or Stage3ApkleaksConfig()
        self.on_progress = on_progress

    def run(self, project_id: str, ctx: RunContext | None = None) -> Run:
        ctx, run_dir, apk_path, run = prepare_stage3_run(self.storage, project_id, ctx)
        log = build_stage3_logger(run_dir / "logs" / "stage3_apkleaks.txt", self.on_progress)

        log("Запущен анализ APKLeaks на этапе 3.")
        emit_progress(self.on_progress, "Запуск анализа APKLeaks для этапа 3...")
        try:
            ensure_apk_ready(apk_path)
            config = ApkleaksConfig(
                timeout_sec=self.config.apkleaks_timeout_sec,
                patterns_json=Path(self.config.apkleaks_patterns_json)
                if self.config.apkleaks_patterns_json
                else None,
                args_string=self.config.apkleaks_args_string,
            )
            runner = ApkleaksRunner(config=config, on_progress=log)
            tool_index = runner.run(ctx, apk_path)
            tool_result_path = resolve_tool_result_path(run_dir, tool_index, "apkleaks")
            tool_ok, exit_code = read_tool_ok(tool_result_path)
            if not tool_ok:
                suffix = f" (exit_code={exit_code})" if exit_code is not None else ""
                raise RuntimeError(f"Анализ APKLeaks завершился ошибкой{suffix}.")

            run.status = "Done"
            run.finished_at = now_utc_iso()
            report_manager = ReportManager(self.storage)
            _, html_path = report_manager.generate_stage3(run, run_dir, None, None)
            run.report_path = str(html_path)
            log("Анализ APKLeaks на этапе 3 завершён.")
            return run
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"Анализ APKLeaks на этапе 3 завершился ошибкой: {exc}")
            run.status = "Error"
            run.finished_at = now_utc_iso()
            append_run_error(run, f"APKLeaks на этапе 3 завершился ошибкой: {exc}")
            report_manager = ReportManager(self.storage)
            report_manager.generate_stage3(run, run_dir, None, None)
            raise
        finally:
            indicators = normalize_stage3(ctx, None, None)
            finalize_stage3_run(ctx, indicators)
