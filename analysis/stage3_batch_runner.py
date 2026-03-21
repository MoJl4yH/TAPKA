from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from analysis.mobsf import DEFAULT_MOBSF_URL, ensure_mobsf_ready, normalize_base_url
from analysis.mobsf.stage3_runner import Stage3Config, Stage3MobSFRunner
from analysis.apkid.stage3_runner import Stage3ApkidConfig, Stage3ApkidRunner
from analysis.apkleaks.stage3_runner import Stage3ApkleaksConfig, Stage3ApkleaksRunner
from analysis.quark.stage3_runner import Stage3QuarkConfig, Stage3QuarkRunner
from analysis.settings import get_mobsf_api_key, load_settings, set_mobsf_api_key
from analysis.storage import Storage
from models import Run


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _detect_emulator() -> str | None:
    """Return the ADB serial of the first connected emulator, or None."""
    try:
        result = subprocess.run(
            ["adb", "devices"], capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                return parts[0]
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    return None


@dataclass
class Stage3BatchConfig:
    mobsf_config: Stage3Config = field(default_factory=Stage3Config)
    quark_config: Stage3QuarkConfig = field(default_factory=Stage3QuarkConfig)
    apkid_config: Stage3ApkidConfig = field(default_factory=Stage3ApkidConfig)
    apkleaks_config: Stage3ApkleaksConfig = field(default_factory=Stage3ApkleaksConfig)
    skip_mobsf: bool = False
    skip_quark: bool = False
    skip_apkid: bool = False
    skip_apkleaks: bool = False
    tool_timeout_sec: int | None = None  # None = без таймаута; переопределяет individual configs

    def __post_init__(self) -> None:
        if self.tool_timeout_sec is not None:
            self.apkid_config.apkid_timeout_sec = self.tool_timeout_sec
            self.apkleaks_config.apkleaks_timeout_sec = self.tool_timeout_sec


class Stage3BatchRunner:
    """Runs all Stage3 tools in a single shared run_dir."""

    def __init__(
        self,
        storage: Storage,
        config: Stage3BatchConfig | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> None:
        self.storage = storage
        self.config = config or Stage3BatchConfig()
        self.on_progress = on_progress or (lambda m: None)

    def run(self, project_id: str) -> dict[str, Run | Exception]:
        ctx = self.storage.get_or_create_stage3_run(project_id)
        results: dict[str, Run | Exception] = {}

        # ── MobSF (container setup + analysis) ──────────────────────────────
        if not self.config.skip_mobsf:
            self.on_progress("=== MobSF: запуск контейнера ===")
            try:
                settings = load_settings()
                mobsf_url = normalize_base_url(
                    settings.get("mobsf", {}).get("url", DEFAULT_MOBSF_URL)
                )
                api_key = get_mobsf_api_key()
                emulator_id = (
                    self.config.mobsf_config.avd_adb_serial
                    or _detect_emulator()
                    or "emulator-5554"  # default tapka AVD serial
                )
                setup = ensure_mobsf_ready(
                    mobsf_url, api_key=api_key,
                    emulator_id=emulator_id,
                    log=self.on_progress,
                )
                # Persist generated key if it's new
                if setup.api_key and setup.api_key != api_key:
                    try:
                        set_mobsf_api_key(setup.api_key)
                    except Exception:  # pylint: disable=broad-exception-caught
                        pass
                self.on_progress("=== MobSF: запуск анализа ===")
                runner = Stage3MobSFRunner(
                    self.storage,
                    config=self.config.mobsf_config,
                    on_progress=self.on_progress,
                )
                run = runner.run(project_id, ctx=ctx)
                results["mobsf"] = run
            except Exception as exc:  # pylint: disable=broad-exception-caught
                self.on_progress(f"MobSF завершился ошибкой: {exc}")
                results["mobsf"] = exc

        # ── APKiD ────────────────────────────────────────────────────────────
        if not self.config.skip_apkid:
            self.on_progress("=== APKiD: запуск анализа ===")
            try:
                runner = Stage3ApkidRunner(
                    self.storage,
                    config=self.config.apkid_config,
                    on_progress=self.on_progress,
                )
                run = runner.run(project_id, ctx=ctx)
                results["apkid"] = run
            except Exception as exc:  # pylint: disable=broad-exception-caught
                self.on_progress(f"APKiD завершился ошибкой: {exc}")
                results["apkid"] = exc

        # ── APKLeaks ─────────────────────────────────────────────────────────
        if not self.config.skip_apkleaks:
            self.on_progress("=== APKLeaks: запуск анализа ===")
            try:
                runner = Stage3ApkleaksRunner(
                    self.storage,
                    config=self.config.apkleaks_config,
                    on_progress=self.on_progress,
                )
                run = runner.run(project_id, ctx=ctx)
                results["apkleaks"] = run
            except Exception as exc:  # pylint: disable=broad-exception-caught
                self.on_progress(f"APKLeaks завершился ошибкой: {exc}")
                results["apkleaks"] = exc

        # ── Quark (last — slowest) ───────────────────────────────────────────
        if not self.config.skip_quark:
            self.on_progress("=== Quark: запуск анализа ===")
            try:
                runner = Stage3QuarkRunner(
                    self.storage,
                    config=self.config.quark_config,
                    on_progress=self.on_progress,
                )
                run = runner.run(project_id, ctx=ctx)
                results["quark"] = run
            except Exception as exc:  # pylint: disable=broad-exception-caught
                self.on_progress(f"Quark завершился ошибкой: {exc}")
                results["quark"] = exc

        # ── Финализация run.json ─────────────────────────────────────────────
        failed = [k for k, v in results.items() if isinstance(v, Exception)]
        enabled_count = sum(1 for skip in (
            self.config.skip_mobsf, self.config.skip_apkid,
            self.config.skip_apkleaks, self.config.skip_quark,
        ) if not skip)
        if enabled_count > 0 and len(failed) == enabled_count:
            overall_status = "Error"
        elif failed:
            overall_status = "Partial"
        else:
            overall_status = "Done"

        run_json_path = ctx.run_dir / "run.json"
        if run_json_path.exists():
            try:
                data = json.loads(run_json_path.read_text(encoding="utf-8"))
                data["status"] = overall_status
                data["finished_at"] = _now_utc()
                run_json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            except (OSError, json.JSONDecodeError):
                pass

        return results
