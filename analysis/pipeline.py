"""Full-pipeline orchestrator: Stage1 → Stage2 → Stage3 + SecurityScore."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from analysis.models.stage2 import Stage2Config
from analysis.stage3_batch_runner import Stage3BatchConfig
from analysis.storage import Storage


@dataclass
class PipelineConfig:
    run_stage2: bool = True
    avd_name: str = "tapka_api30"
    runtime_sec: int = 180
    run_stage3: bool = True
    stage3_config: Stage3BatchConfig | None = None
    report_type: str = "standard"


@dataclass
class PipelineResult:
    project_id: str
    stage1_ok: bool = False
    stage2_ok: bool = False
    stage3_ok: bool = False
    security_score: object | None = None   # analysis.scoring.SecurityScore
    run_dir: Path | None = None
    elapsed_sec: float = 0.0
    errors: list[str] = field(default_factory=list)


def run_full_pipeline(
    apk_path: str | Path,
    storage: Storage,
    config: PipelineConfig | None = None,
    on_progress: Callable[[str], None] | None = None,
    project_id: str | None = None,
) -> PipelineResult:
    """Запускает все стадии для *apk_path* и возвращает PipelineResult.

    Если *project_id* передан — использует существующий проект (не создаёт новый).
    """
    from analysis.scoring import compute_score
    from analysis.stage1_analysis import Stage1StaticRunner
    from analysis.stage2.runner import Stage2DynamicRunner
    from analysis.reporting import ReportManager

    cfg = config or PipelineConfig()
    log = on_progress or (lambda m: None)
    start_ts = time.monotonic()

    # Создаём или используем существующий проект
    if project_id:
        # BUG-CLI-04: validate that the project actually exists before running stages
        try:
            storage.load_project(project_id)
        except (FileNotFoundError, ValueError, OSError) as exc:
            result = PipelineResult(project_id=project_id)
            result.errors.append(f"Invalid project_id '{project_id}': {exc}")
            return result
    else:
        project = storage.create_project(str(apk_path))
        project_id = project.project_id
    result = PipelineResult(project_id=project_id)

    # ── Stage 1 ──────────────────────────────────────────────────────────────
    # Stage1 emits dicts {"message":..,"completed":..,"total":..}, but the
    # pipeline's `log` callback expects plain strings. Adapt here so GUI
    # log views and CLI stdout always receive printable strings.
    def _stage1_log(payload: object) -> None:
        if isinstance(payload, dict):
            parts = []
            msg = payload.get("message", "")
            if msg:
                parts.append(msg)
            completed = int(payload.get("completed", 0))
            total = int(payload.get("total", 0))
            if total:
                parts.append(f"{completed}/{total}")
            elapsed = payload.get("elapsed_sec")
            if elapsed is not None:
                # BUG-CLI-03: guard against non-numeric elapsed_sec
                try:
                    m, s = divmod(int(elapsed), 60)
                    parts.append(f"{m}:{s:02d}" if m else f"{s}s")
                except (ValueError, TypeError):
                    pass
            if parts:
                log("  " + " · ".join(parts))
        else:
            log(str(payload))

    log("=== Pipeline: Stage 1 — Static Analysis ===")
    try:
        runner1 = Stage1StaticRunner(storage, on_progress=_stage1_log)
        runner1.run(project_id)
        result.stage1_ok = True
        log("Stage 1 OK")
    except Exception as exc:  # pylint: disable=broad-exception-caught
        result.errors.append(f"stage1: {exc}")
        log(f"Stage 1 FAILED: {exc}")

    # ── Stage 2 ──────────────────────────────────────────────────────────────
    if cfg.run_stage2:
        log("=== Pipeline: Stage 2 — Dynamic Analysis ===")
        try:
            cfg2 = Stage2Config(
                avd_name=cfg.avd_name,
                runtime_duration_sec=cfg.runtime_sec,
            )
            runner2 = Stage2DynamicRunner(storage, config=cfg2, on_progress=log)
            run2 = runner2.run(project_id)
            result.stage2_ok = run2.status == "Done"
            log(f"Stage 2 {'OK' if result.stage2_ok else f'завершён со статусом: {run2.status}'}")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            result.errors.append(f"stage2: {exc}")
            log(f"Stage 2 FAILED: {exc}")

    # ── Пауза между Stage 2 и Stage 3 ───────────────────────────────────────
    # Даём ОС 15 секунд освободить память после остановки QEMU-эмулятора
    # перед тем как Stage 3 MobSF запустит новый эмулятор.
    if cfg.run_stage2 and cfg.run_stage3:
        log("Pipeline: ожидание освобождения памяти после Stage 2 (15s)...")
        time.sleep(15)

    # ── Stage 3 ──────────────────────────────────────────────────────────────
    if cfg.run_stage3:
        log("=== Pipeline: Stage 3 — Cross-tool Analysis ===")
        try:
            from analysis.stage3_batch_runner import Stage3BatchRunner

            s3_cfg = cfg.stage3_config or Stage3BatchConfig()
            runner3 = Stage3BatchRunner(storage, config=s3_cfg, on_progress=log)
            # BUG-PIPE-02: check actual results dict instead of assuming success
            results3 = runner3.run(project_id)
            result.stage3_ok = all(not isinstance(r, Exception) for r in results3.values())
            log(f"Stage 3 {'OK' if result.stage3_ok else 'завершён с ошибками'}")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            result.errors.append(f"stage3: {exc}")
            log(f"Stage 3 FAILED: {exc}")

    # ── Security Score ────────────────────────────────────────────────────────
    try:
        from analysis.reporting import ReportManager as RM, ReportType

        rm = RM(storage)
        findings_by_stage = rm.load_all_findings(project_id)
        result.security_score = compute_score(findings_by_stage)
        log(f"Security Score: {result.security_score.total:.1f} ({result.security_score.risk_label})")
    except Exception as exc:  # pylint: disable=broad-exception-caught
        result.errors.append(f"scoring: {exc}")

    # ── Save combined report ──────────────────────────────────────────────────
    try:
        from analysis.reporting import ReportManager as RM2, ReportType as RT2

        rm2 = RM2(storage)
        combined = rm2.generate_combined_report(project_id, RT2.EXTENDED)
        # BUG-ARCH-09: guard against get_active_version_dir failure
        try:
            version_dir = storage.get_active_version_dir(project_id)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"[WARN] Не удалось получить version_dir: {exc}")
            version_dir = storage.get_project_dir(project_id)
        overall_path = version_dir / "overall_report.json"
        overall_path.write_text(combined.model_dump_json(indent=2, by_alias=True), encoding="utf-8")
        log(f"Combined report: {overall_path}")
    except Exception as exc:  # pylint: disable=broad-exception-caught
        result.errors.append(f"combined_report: {exc}")

    result.elapsed_sec = round(time.monotonic() - start_ts, 1)
    return result
