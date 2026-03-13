from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from analysis.mobsf import DEFAULT_MOBSF_URL, ensure_mobsf_ready, normalize_base_url
from analysis.mobsf.stage3_runner import Stage3Config, Stage3MobSFRunner
from analysis.apkid.stage3_runner import Stage3ApkidConfig, Stage3ApkidRunner
from analysis.apkleaks.stage3_runner import Stage3ApkleaksConfig, Stage3ApkleaksRunner
from analysis.quark.stage3_runner import Stage3QuarkConfig, Stage3QuarkRunner
from analysis.settings import get_mobsf_api_key, load_settings, set_mobsf_api_key
from analysis.storage import Storage
from models import Run


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
                setup = ensure_mobsf_ready(mobsf_url, api_key=api_key, log=self.on_progress)
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

        return results
