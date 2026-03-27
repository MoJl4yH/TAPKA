from __future__ import annotations

import json
import os
import subprocess
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import requests

from analysis.mobsf import DEFAULT_MOBSF_URL, normalize_base_url
from analysis.mobsf.client import MobSFClient, MobSFClientError, MobSFResponse
from analysis.quark import QuarkConfig, QuarkRunner
from analysis.runtime.clock import now_utc_iso
from analysis.runtime.context import RunContext
from analysis.normalize.stage3 import normalize_stage3
from analysis.stage3_common import (
    append_run_error,
    build_stage3_logger,
    emit_progress,
    ensure_apk_ready,
    finalize_stage3_run,
    prepare_stage3_run,
)
from analysis.runtime.fs import (
    clear_tool_dir,
    write_tool_bundle,
)
from analysis.models.mobsf import (
    MobSFArtifacts,
    MobSFDynamicAndroidSummary,
    MobSFFeatureFlags,
    MobSFInstanceInfo,
    MobSFIosSummary,
    MobSFAppSecFinding,
    MobSFReport,
    MobSFStaticSummary,
)
from analysis.models.quark import QuarkReport
from analysis.reporting import ReportManager
from analysis.settings import load_settings, get_mobsf_api_key
from analysis.storage import Storage
from models import Run


@dataclass
class Stage3Config:
    enable_dynamic_android: bool = False
    enable_dynamic_v2: bool = False        # Use improved dynamic workflow (mobsfy + CA + proxy + wait)
    enable_ios: bool = False
    enable_quark: bool = False
    cleanup_scans: bool = False
    download_pdf: bool = False
    view_source: bool = False
    frida_steps: bool = False
    tls_tests: bool = False
    quark_timeout_sec: int = 1800
    quark_rules_dir: str | None = None
    view_source_files: list[tuple[str, str]] = field(default_factory=list)
    dynamic_view_source_files: list[tuple[str, str]] = field(default_factory=list)
    # default hooks: all standard MobSF scripts that are useful for security analysis
    # (api_monitor, ssl_pinning_bypass, root_bypass, debugger_check_bypass, dump_clipboard)
    frida_default_hooks: str = (
        "api_monitor,ssl_pinning_bypass,root_bypass,debugger_check_bypass,dump_clipboard"
    )
    # auxiliary hooks: enumerate loaded classes and catch string operations
    frida_auxiliary_hooks: str = "enum_class,string_catch"
    frida_code: str = ""
    monkey_events: int = 150          # 0 = skip; random UI events via adb monkey
    monkey_throttle_ms: int = 200     # ms between monkey events (~30s for 150 events)
    avd_adb_serial: str | None = None     # ADB serial to pass directly to MobSF mobsfy
    avd_name: str = "tapka_api30"         # AVD name for emulator restart
    restart_emulator: bool = True         # Wipe + restart emulator before dynamic analysis for clean state
    emulator_cpu_cores: int | None = None  # None = auto (os.cpu_count() // 2)


class Stage3MobSFRunner:
    def __init__(
        self,
        storage: Storage,
        config: Stage3Config | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> None:
        self.storage = storage
        self.config = config or Stage3Config()
        self.on_progress = on_progress

    def run(self, project_id: str, ctx: RunContext | None = None) -> Run:
        ctx, run_dir, apk_path, run = prepare_stage3_run(self.storage, project_id, ctx)
        tools_index = ctx.meta.setdefault("tools_index", [])
        tools_index[:] = [entry for entry in tools_index if entry.get("tool") != "mobsf"]
        clear_tool_dir(ctx, "mobsf")
        mobsf_cmd = ["mobsf_api", "scan", str(apk_path)]
        mobsf_started_at = now_utc_iso()
        mobsf_exit_code = 0
        mobsf_stdout = ""
        mobsf_stderr = ""
        mobsf_written = False
        log_path = run_dir / "logs" / "stage3_mobsf.txt"
        log = build_stage3_logger(log_path, self.on_progress)
        artifacts_root = run_dir / "artifacts" / "mobsf"
        static_dir = artifacts_root / "static"
        dynamic_dir = artifacts_root / "dynamic_android"
        ios_dir = artifacts_root / "ios"
        trace_dir = artifacts_root / "http_trace"
        for path in (static_dir, dynamic_dir, ios_dir, trace_dir):
            path.mkdir(parents=True, exist_ok=True)
        quark_dir = None
        if self.config.enable_quark:
            quark_dir = run_dir / "artifacts" / "quark"
            quark_dir.mkdir(parents=True, exist_ok=True)

        start_time = now_utc_iso()
        log("Запущен анализ MobSF на этапе 3.")
        emit_progress(self.on_progress, "Запуск анализа MobSF для этапа 3...")

        mobsf_report = None
        quark_report = None
        try:
            base_url, api_key = self._resolve_mobsf_settings()
            client = MobSFClient(base_url, api_key)

            self._emit("Проверка доступности MobSF...")
            self._check_available(client)

            ensure_apk_ready(apk_path)
            apk_display_name = self._resolve_apk_display_name(project_id, apk_path)
            self._validate_upload_file(apk_path, apk_display_name, log)

            static_summary, dynamic_summary, ios_summary, artifacts = self._run_pipeline(
                client,
                run_dir,
                apk_path,
                apk_display_name,
                static_dir,
                dynamic_dir,
                ios_dir,
                trace_dir,
                log,
            )
            mobsf_finished_at = now_utc_iso()
            tools_index.append(
                self._record_mobsf_tool_result(
                    ctx,
                    mobsf_cmd,
                    mobsf_started_at,
                    mobsf_finished_at,
                    mobsf_exit_code,
                    mobsf_stdout,
                    mobsf_stderr,
                    artifacts_root,
                    static_dir,
                    dynamic_dir,
                    ios_dir,
                    trace_dir,
                )
            )
            mobsf_written = True
            if self.config.enable_quark and quark_dir:
                quark_report = self._run_quark(apk_path, quark_dir, run_dir, log, ctx=ctx)

            run.status = "Done"
            run.finished_at = now_utc_iso()

            mobsf_report = self._build_report(
                base_url,
                start_time,
                static_summary,
                dynamic_summary,
                ios_summary,
                artifacts,
            )

            report_manager = ReportManager(self.storage)
            _, html_path = report_manager.generate_stage3(run, run_dir, mobsf_report, quark_report)
            run.report_path = str(html_path)
            log("Анализ MobSF на этапе 3 завершён.")
            return run
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"Анализ MobSF на этапе 3 завершился ошибкой: {exc}")
            run.status = "Error"
            run.finished_at = now_utc_iso()
            append_run_error(run, f"MobSF на этапе 3 завершился ошибкой: {exc}")
            report = self._build_error_report(start_time)
            report_manager = ReportManager(self.storage)
            report_manager.generate_stage3(run, run_dir, report, None)
            mobsf_exit_code = 1
            mobsf_stderr = str(exc)
            if not mobsf_written:
                mobsf_finished_at = now_utc_iso()
                tools_index.append(
                    self._record_mobsf_tool_result(
                        ctx,
                        mobsf_cmd,
                        mobsf_started_at,
                        mobsf_finished_at,
                        mobsf_exit_code,
                        mobsf_stdout,
                        mobsf_stderr,
                        artifacts_root,
                        static_dir,
                        dynamic_dir,
                        ios_dir,
                        trace_dir,
                    )
                )
            raise
        finally:
            indicators = normalize_stage3(ctx, mobsf_report, quark_report)
            finalize_stage3_run(ctx, indicators)

    def _record_mobsf_tool_result(
        self,
        ctx: RunContext,
        cmd: list[str],
        started_at: str,
        finished_at: str,
        exit_code: int,
        stdout: str,
        stderr: str,
        artifacts_root: Path,
        static_dir: Path,
        dynamic_dir: Path,
        ios_dir: Path,
        trace_dir: Path,
    ) -> dict[str, str]:
        artifacts = self._collect_mobsf_artifacts(
            ctx,
            artifacts_root,
            static_dir,
            dynamic_dir,
            ios_dir,
            trace_dir,
        )
        return write_tool_bundle(
            ctx,
            "mobsf",
            cmd,
            started_at,
            finished_at,
            exit_code,
            stdout,
            stderr,
            artifacts,
        )

    def _collect_mobsf_artifacts(
        self,
        ctx: RunContext,
        artifacts_root: Path,
        static_dir: Path,
        dynamic_dir: Path,
        ios_dir: Path,
        trace_dir: Path,
    ) -> dict[str, str]:
        artifacts: dict[str, str] = {}
        for name, path in (
            ("artifacts_dir", artifacts_root),
            ("static_dir", static_dir),
            ("dynamic_dir", dynamic_dir),
            ("ios_dir", ios_dir),
            ("trace_dir", trace_dir),
        ):
            if path.exists():
                relpath = os.path.relpath(path, ctx.run_dir)
                if path.is_dir():
                    relpath += "/"
                artifacts[name] = relpath
        return artifacts

    def _run_pipeline(
        self,
        client: MobSFClient,
        run_dir: Path,
        apk_path: Path,
        apk_display_name: str,
        static_dir: Path,
        dynamic_dir: Path,
        _ios_dir: Path,
        trace_dir: Path,
        log: Callable[[str], None],
    ) -> tuple[MobSFStaticSummary, MobSFDynamicAndroidSummary, MobSFIosSummary, MobSFArtifacts]:
        artifacts = MobSFArtifacts()
        static_summary = MobSFStaticSummary()
        dynamic_summary = MobSFDynamicAndroidSummary(enabled=self.config.enable_dynamic_android)
        ios_summary = MobSFIosSummary(enabled=self.config.enable_ios, status="Не настроено")
        static_artifacts = dict(artifacts.static) if isinstance(artifacts.static, dict) else {}
        dynamic_android_artifacts = (
            dict(artifacts.dynamic_android) if isinstance(artifacts.dynamic_android, dict) else {}
        )

        self._emit("Загрузка APK в MobSF...")
        upload_resp = self._call_and_save_json(
            lambda: client.upload(str(apk_path), filename=apk_display_name),
            static_dir / "upload.json",
            trace_dir,
            "static_upload",
        )
        upload_data = upload_resp.json_data or {}
        scan_hash = upload_data.get("hash")
        scan_type = upload_data.get("scan_type")
        static_summary.scan_hash = scan_hash
        static_summary.scan_type = scan_type
        static_artifacts["upload"] = self._relpath(run_dir, static_dir / "upload.json")

        if not scan_hash:
            raise RuntimeError("MobSF не вернул хэш сканирования после загрузки файла.")

        self._emit("Запуск статического анализа MobSF...")
        self._emit_scan_status("Сканирование запущено")
        self._call_and_save_json(
            lambda: client.scan(scan_hash),
            static_dir / "scan.json",
            trace_dir,
            "static_scan",
        )
        static_artifacts["scan"] = self._relpath(run_dir, static_dir / "scan.json")

        self._emit("Получение журналов сканирования MobSF...")
        scan_logs_resp = self._call_and_save_text(
            lambda: client.scan_logs(scan_hash),
            static_dir / "scan_logs.txt",
            trace_dir,
            "static_scan_logs",
        )
        scan_status = self._scan_status_from_logs(scan_logs_resp.json_data)
        if scan_status:
            self._emit_scan_status(scan_status)
        static_artifacts["scan_logs"] = self._relpath(run_dir, static_dir / "scan_logs.txt")

        self._emit("Получение JSON-отчёта статического анализа MobSF...")
        report_resp = self._call_and_save_json(
            lambda: client.report_json(scan_hash),
            static_dir / "report.json",
            trace_dir,
            "static_report_json",
        )
        static_artifacts["report_json"] = self._relpath(run_dir, static_dir / "report.json")
        static_summary = self._extract_static_summary(report_resp.json_data, static_summary)
        self._emit_scan_status("Сканирование завершено")

        self._emit("Получение сводной оценки MobSF...")
        scorecard_resp = self._call_and_save_json(
            lambda: client.scorecard(scan_hash),
            static_dir / "scorecard.json",
            trace_dir,
            "static_scorecard",
        )
        static_artifacts["scorecard"] = self._relpath(run_dir, static_dir / "scorecard.json")
        static_summary.scorecard = scorecard_resp.json_data or {}

        if self.config.download_pdf:
            self._emit("Загрузка PDF-отчёта MobSF...")
            pdf_path = static_dir / "report.pdf"
            pdf_response = client.download_pdf(scan_hash)
            self._write_trace(trace_dir, "static_download_pdf", pdf_response.status_code)
            if pdf_response.status_code >= 400:
                snippet = self._short_text(pdf_response.text)
                raise MobSFClientError(
                    f"Ошибка API MobSF (HTTP {pdf_response.status_code}) при загрузке PDF: {snippet}"
                )
            self._write_binary(pdf_path, pdf_response.content)
            static_artifacts["report_pdf"] = self._relpath(run_dir, pdf_path)

        if self.config.view_source and self.config.view_source_files:
            view_dir = static_dir / "view_source"
            view_dir.mkdir(parents=True, exist_ok=True)
            for file_path, source_type in self.config.view_source_files:
                self._emit(f"Получение исходного файла: {file_path}")
                self._call_and_save_json(
                    lambda fp=file_path, st=source_type: client.view_source(scan_hash, fp, st),
                    view_dir / f"{self._safe_name(file_path)}.json",
                    trace_dir,
                    f"static_view_source_{self._safe_name(file_path)}",
                )
            static_artifacts["view_source"] = self._relpath(run_dir, view_dir)
        elif self.config.view_source:
            log("Режим просмотра исходников включён, но список файлов не задан.")

        if self.config.enable_dynamic_android:
            try:
                if self.config.enable_dynamic_v2:
                    # Extract main_activity from static report — API docs confirm that
                    # dynamic_start_analysis response does NOT include activities.
                    static_main_activity = ""
                    if isinstance(report_resp.json_data, dict):
                        static_main_activity = report_resp.json_data.get("main_activity") or ""
                    dynamic_summary, dynamic_artifacts = self._run_dynamic_android_v2(
                        client,
                        scan_hash,
                        dynamic_dir,
                        trace_dir,
                        log,
                        run_dir,
                        dynamic_summary,
                        main_activity=static_main_activity,
                    )
                else:
                    dynamic_summary, dynamic_artifacts = self._run_dynamic_android(
                        client,
                        scan_hash,
                        dynamic_dir,
                        trace_dir,
                        log,
                        run_dir,
                        dynamic_summary,
                    )
                dynamic_android_artifacts.update(dynamic_artifacts)
            except MobSFClientError as _dyn_exc:  # pylint: disable=broad-exception-caught
                dynamic_summary.status = "failed"
                log(f"[WARN] Динамический анализ MobSF пропущен: {_dyn_exc}")

        if self.config.cleanup_scans:
            self._emit("Очистка данных сканирования MobSF...")
            self._call_and_save_json(
                lambda: client.delete_scan(scan_hash),
                static_dir / "delete_scan.json",
                trace_dir,
                "static_delete_scan",
            )
            static_artifacts["delete_scan"] = self._relpath(run_dir, static_dir / "delete_scan.json")

        artifacts.static = static_artifacts
        artifacts.dynamic_android = dynamic_android_artifacts

        return static_summary, dynamic_summary, ios_summary, artifacts

    def _run_dynamic_android(
        self,
        client: MobSFClient,
        scan_hash: str,
        dynamic_dir: Path,
        trace_dir: Path,
        log: Callable[[str], None],
        run_dir: Path,
        summary: MobSFDynamicAndroidSummary,
    ) -> tuple[MobSFDynamicAndroidSummary, dict[str, str]]:
        artifacts: dict[str, str] = {}
        self._emit("Запуск динамического анализа MobSF...")
        start_resp = self._call_and_save_json(
            lambda: client.dynamic_start_analysis(scan_hash),
            dynamic_dir / "start.json",
            trace_dir,
            "dynamic_start",
        )
        summary.status = "running"
        artifacts["start"] = self._relpath(run_dir, dynamic_dir / "start.json")

        package_name = None
        if isinstance(start_resp.json_data, dict):
            package_name = start_resp.json_data.get("package")

        if package_name:
            self._emit("Сбор logcat...")
            self._call_and_save_text(
                lambda: client.android_logcat(package_name),
                dynamic_dir / "logcat.txt",
                trace_dir,
                "dynamic_logcat",
            )
            summary.logcat_lines = self._line_count(dynamic_dir / "logcat.txt")
            artifacts["logcat"] = self._relpath(run_dir, dynamic_dir / "logcat.txt")

        if self.config.tls_tests:
            self._emit("Выполнение TLS-проверок...")
            tls_resp = self._call_and_save_json(
                lambda: client.android_tls_tests(scan_hash),
                dynamic_dir / "tls_tests.json",
                trace_dir,
                "dynamic_tls_tests",
            )
            if isinstance(tls_resp.json_data, dict):
                summary.tls_tests = tls_resp.json_data.get("tls_tests", tls_resp.json_data)
            artifacts["tls_tests"] = self._relpath(run_dir, dynamic_dir / "tls_tests.json")

        if self.config.frida_steps:
            frida_dir = dynamic_dir / "frida"
            frida_dir.mkdir(parents=True, exist_ok=True)
            self._emit("Запуск инструментирования Frida...")
            self._call_and_save_json(
                lambda: client.frida_instrument(
                    scan_hash,
                    self.config.frida_default_hooks,
                    self.config.frida_auxiliary_hooks,
                    self.config.frida_code,
                ),
                frida_dir / "instrument.json",
                trace_dir,
                "dynamic_frida_instrument",
            )
            self._emit("Сбор данных монитора API Frida...")
            self._call_and_save_json(
                lambda: client.frida_api_monitor(scan_hash),
                frida_dir / "api_monitor.json",
                trace_dir,
                "dynamic_frida_api_monitor",
            )
            self._emit("Сбор журналов Frida...")
            self._call_and_save_json(
                lambda: client.frida_logs(scan_hash),
                frida_dir / "logs.json",
                trace_dir,
                "dynamic_frida_logs",
            )
            self._emit("Сбор зависимостей приложения (Frida)...")
            try:
                self._call_and_save_json(
                    lambda: client.frida_get_dependencies(scan_hash),
                    frida_dir / "dependencies.json",
                    trace_dir,
                    "dynamic_frida_dependencies",
                )
            except MobSFClientError as exc:
                log(f"[WARN] frida_get_dependencies: {exc}")
            artifacts["frida"] = self._relpath(run_dir, frida_dir)

        self._emit("Остановка динамического анализа...")
        self._call_and_save_json(
            lambda: client.dynamic_stop_analysis(scan_hash),
            dynamic_dir / "stop.json",
            trace_dir,
            "dynamic_stop",
        )
        summary.status = "stopped"
        artifacts["stop"] = self._relpath(run_dir, dynamic_dir / "stop.json")

        self._emit("Получение JSON-отчёта динамического анализа...")
        self._call_and_save_json(
            lambda: client.dynamic_report_json(scan_hash),
            dynamic_dir / "report.json",
            trace_dir,
            "dynamic_report_json",
        )
        artifacts["report_json"] = self._relpath(run_dir, dynamic_dir / "report.json")

        if self.config.dynamic_view_source_files:
            view_dir = dynamic_dir / "view_source"
            view_dir.mkdir(parents=True, exist_ok=True)
            for file_path, file_type in self.config.dynamic_view_source_files:
                self._emit(f"Получение динамического исходного файла: {file_path}")
                self._call_and_save_json(
                    lambda fp=file_path, ft=file_type: client.dynamic_view_source(scan_hash, fp, ft),
                    view_dir / f"{self._safe_name(file_path)}.json",
                    trace_dir,
                    f"dynamic_view_source_{self._safe_name(file_path)}",
                )
            artifacts["view_source"] = self._relpath(run_dir, view_dir)

        return summary, artifacts

    def _get_emulator_identifier(self) -> str:
        """Return the serial of the first connected emulator via adb devices."""
        # avd_adb_serial must be an actual ADB serial (e.g. emulator-5554), not an AVD name
        if self.config.avd_adb_serial and self.config.avd_adb_serial.startswith("emulator-"):
            return self.config.avd_adb_serial
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
        return "emulator-5554"

    def _wait_for_app_launch(
        self,
        client: MobSFClient,
        package: str,
        timeout_sec: int = 60,
    ) -> None:
        """Poll logcat until the package appears in output or timeout is reached."""
        start = time.monotonic()
        while time.monotonic() - start < timeout_sec:
            try:
                resp = client.android_logcat(package)
                if resp.status_code == 200 and package in (resp.text or ""):
                    self._emit(f"Приложение {package} запущено")
                    return
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            time.sleep(3)
        self._emit(f"Timeout ожидания запуска {package} ({timeout_sec}s)")

    def _wait_for_app_launch_adb(
        self,
        serial: str,
        package: str,
        timeout_sec: int = 60,
    ) -> None:
        """Wait for the app process to appear in adb shell ps (no MobSF streaming)."""
        adb = ["adb", "-s", serial]
        start = time.monotonic()
        while time.monotonic() - start < timeout_sec:
            try:
                r = subprocess.run(
                    adb + ["shell", "ps", "-A"],
                    capture_output=True, text=True, timeout=10,
                )
                if package in (r.stdout or ""):
                    self._emit(f"Приложение {package} запущено")
                    return
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            time.sleep(3)
        self._emit(f"Timeout ожидания запуска {package} ({timeout_sec}s)")

    def _collect_logcat_adb(
        self,
        serial: str,
        package: str,
        output_path: Path,
    ) -> None:
        """Collect logcat dump via direct ADB (avoids MobSF SSE streaming endpoint)."""
        try:
            r = subprocess.run(
                ["adb", "-s", serial, "logcat", "-d", f"{package}:V", "*:S"],
                capture_output=True, text=True, timeout=30,
            )
            output_path.write_text(r.stdout or "", encoding="utf-8", errors="replace")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._emit(f"[WARN] logcat adb: {exc}")

    def _run_dynamic_android_v2(
        self,
        client: MobSFClient,
        scan_hash: str,
        dynamic_dir: Path,
        trace_dir: Path,
        log: Callable[[str], None],
        run_dir: Path,
        summary: MobSFDynamicAndroidSummary,
        main_activity: str = "",
    ) -> tuple[MobSFDynamicAndroidSummary, dict[str, str]]:
        """Orchestrated dynamic analysis workflow.

        Steps:
        1. mobsfy  — connect emulator to MobSF
        2. root_ca — install MobSF CA certificate
        3. proxy   — set global proxy
        4. start   — launch dynamic analysis
        5. wait    — poll logcat until app launches
        6. tls     — TLS tests (if enabled)
        7. frida   — instrumentation (if enabled)
        8. stop    — stop dynamic analysis
        9. report  — fetch dynamic report JSON
        """
        artifacts: dict[str, str] = {}
        self._emit("Запуск оркестрированного динамического анализа MobSF (v2)...")

        # 0. Restart emulator with -wipe-data for a clean state before each analysis run
        mgr = None
        if self.config.restart_emulator:
            from analysis.stage2.emulator import EmulatorManager  # noqa: PLC0415
            self._emit(f"Перезапуск эмулятора {self.config.avd_name} (wipe-data)...")
            mgr = EmulatorManager(
                avd_name=self.config.avd_name,
                on_log=log,
                cpu_cores=self.config.emulator_cpu_cores,
            )
            mgr.start(headless=True)
            if not mgr.wait_boot(timeout_sec=480):
                raise RuntimeError("Emulator failed to boot within 480s")
            mgr.root()
            # frida 16+ marks Android as "jailed" when SELinux is Enforcing,
            # causing NotSupportedError on spawn/attach. Disable enforcement.
            emulator_serial = self._get_emulator_identifier()
            subprocess.run(
                ["adb", "-s", emulator_serial, "shell", "setenforce", "0"],
                capture_output=True, timeout=10, check=False,
            )

        # 1. Connect emulator to MobSF
        emulator_id = self._get_emulator_identifier()
        self._emit(f"Подключение эмулятора {emulator_id} к MobSF (mobsfy)...")

        # MobSF supports dynamic analysis only up to ANDROID_API_SUPPORTED = 30 (Android 11).
        # Check before wasting time on bridge setup.
        self._check_mobsf_api_level(emulator_id)

        # Apply TAPKA compatibility patches to MobSF container (idempotent).
        # Redirects /system writes (frida-server, .mobsf-f) to /data/local/tmp.
        from analysis.mobsf import apply_mobsf_patches, _is_mobsf_patched  # noqa: PLC0415
        if not _is_mobsf_patched():
            apply_mobsf_patches(log=log)

        # MobSF translates emulator-5554 → host.docker.internal:5555 internally.
        # host.docker.internal resolves to the Docker bridge IP (172.17.0.1) via
        # --add-host host.docker.internal:host-gateway in docker_run().
        # But QEMU binds the emulator ADB port only on 127.0.0.1:5555, not on the
        # bridge IP. Fix: enable TCP mode on adbd, then run socat to forward
        # bridge_ip:5555 → 127.0.0.1:5555 so MobSF can reach the emulator.
        adb_bridge_proc = self._setup_adb_bridge(emulator_id)
        # After adb root, adbd restarts briefly — wait until device is back online
        # before running adb shell commands (cacerts bind-mount, etc.)
        subprocess.run(
            ["adb", "-s", emulator_id, "wait-for-device"],
            capture_output=True, timeout=30, check=False,
        )
        self._setup_cacerts_bindmount(emulator_id, log)
        try:
            self._call_and_save_json(
                lambda: client.android_mobsfy(emulator_id),
                dynamic_dir / "mobsfy.json",
                trace_dir,
                "dynamic_mobsfy",
            )
            artifacts["mobsfy"] = self._relpath(run_dir, dynamic_dir / "mobsfy.json")

            # 2. Install MobSF CA
            self._emit("Установка MobSF CA сертификата...")
            self._call_and_save_json(
                lambda: client.android_root_ca("install"),
                dynamic_dir / "root_ca_install.json",
                trace_dir,
                "dynamic_root_ca_install",
            )
            artifacts["root_ca_install"] = self._relpath(
                run_dir, dynamic_dir / "root_ca_install.json"
            )

            # 3. Set global proxy
            self._emit("Установка глобального прокси на эмуляторе...")
            self._call_and_save_json(
                lambda: client.android_global_proxy("set"),
                dynamic_dir / "proxy_set.json",
                trace_dir,
                "dynamic_proxy_set",
            )
            artifacts["proxy_set"] = self._relpath(run_dir, dynamic_dir / "proxy_set.json")

            # 4. Start dynamic analysis
            self._emit("Запуск динамического анализа MobSF...")
            start_resp = self._call_and_save_json(
                lambda: client.dynamic_start_analysis(scan_hash),
                dynamic_dir / "start.json",
                trace_dir,
                "dynamic_start",
            )
            summary.status = "running"
            artifacts["start"] = self._relpath(run_dir, dynamic_dir / "start.json")

            package_name = ""
            if isinstance(start_resp.json_data, dict):
                package_name = start_resp.json_data.get("package") or ""

            # 5. Launch the app — dynamic_start_analysis only installs/prepares the env;
            #    it does NOT start the activity (confirmed by MobSF API docs).
            #    We use main_activity from the static report (passed in); fallback to monkey.
            if package_name:
                if main_activity:
                    self._emit(f"Запуск приложения {main_activity}...")
                    try:
                        self._call_and_save_json(
                            lambda: client.android_start_activity(scan_hash, main_activity),
                            dynamic_dir / "start_activity.json",
                            trace_dir,
                            "dynamic_start_activity",
                        )
                    except MobSFClientError as exc:
                        log(f"[WARN] android_start_activity: {exc}")
                        # Fallback: launch directly via ADB
                        subprocess.run(
                            ["adb", "-s", emulator_id, "shell", "am", "start",
                             "-n", f"{package_name}/{main_activity}"],
                            capture_output=True, timeout=15,
                        )
                else:
                    # No activity info — use monkey to launch
                    subprocess.run(
                        ["adb", "-s", emulator_id, "shell", "monkey",
                         "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
                        capture_output=True, timeout=15,
                    )

            # Wait for app to appear in process list
            wait_sec = 60
            if package_name:
                self._emit(f"Ожидание запуска приложения ({wait_sec}s)...")
                self._wait_for_app_launch_adb(emulator_id, package_name, timeout_sec=wait_sec)

            # 5b. Activity tester — запускает все Activity и exported Activity через MobSF API,
            #     чтобы спровоцировать сетевой трафик и API-вызовы без ручного взаимодействия.
            self._emit("Запуск тестера Activity (все + exported)...")
            for test_type, fname in (("activity", "activity_tester.json"), ("exported", "activity_tester_exported.json")):
                try:
                    self._call_and_save_json(
                        lambda t=test_type: client.android_activity(scan_hash, t),
                        dynamic_dir / fname,
                        trace_dir,
                        f"dynamic_{fname.replace('.json', '')}",
                    )
                except MobSFClientError as exc:
                    log(f"[WARN] Activity tester ({test_type}): {exc}")
            # Дать тестеру время отработать перед следующим шагом
            time.sleep(15)

            # 6. TLS tests (non-fatal — app may not be running)
            if self.config.tls_tests:
                self._emit("Выполнение TLS-проверок...")
                try:
                    tls_resp = self._call_and_save_json(
                        lambda: client.android_tls_tests(scan_hash),
                        dynamic_dir / "tls_tests.json",
                        trace_dir,
                        "dynamic_tls_tests",
                    )
                    if isinstance(tls_resp.json_data, dict):
                        summary.tls_tests = tls_resp.json_data.get("tls_tests", tls_resp.json_data)
                    artifacts["tls_tests"] = self._relpath(run_dir, dynamic_dir / "tls_tests.json")
                except MobSFClientError as exc:
                    log(f"[WARN] TLS-проверки пропущены: {exc}")

            # 7. Frida instrumentation (non-fatal — requires frida-server on device)
            if self.config.frida_steps:
                frida_dir = dynamic_dir / "frida"
                frida_dir.mkdir(parents=True, exist_ok=True)
                frida_ok = False
                try:
                    self._emit("Запуск инструментирования Frida...")
                    # Use frida_action="session" to attach to the already-running app.
                    # default_hooks: api_monitor + ssl/root/debugger bypasses + clipboard
                    # auxiliary_hooks: enum_class + string_catch for deep coverage
                    self._call_and_save_json(
                        lambda: client.frida_instrument(
                            scan_hash,
                            self.config.frida_default_hooks,
                            self.config.frida_auxiliary_hooks,
                            self.config.frida_code,
                            frida_action="session",
                        ),
                        frida_dir / "instrument.json",
                        trace_dir,
                        "dynamic_frida_instrument",
                    )
                    frida_ok = True
                except MobSFClientError as exc:
                    log(f"[WARN] Frida инструментирование пропущено: {exc}")

                if frida_ok:
                    # 7b. Activity tester (второй прогон) — пока Frida hooks активны.
                    # Первый прогон (до Frida) дал скриншоты + трафик через прокси.
                    # Второй прогон позволяет Frida перехватить API-вызовы от запуска
                    # каждой Activity (crypto, storage, network, reflection и т.д.).
                    self._emit("Повторный тестер Activity (Frida-покрытие)...")
                    for test_type, fname in (
                        ("activity", "activity_tester_frida.json"),
                        ("exported", "activity_tester_exported_frida.json"),
                    ):
                        try:
                            self._call_and_save_json(
                                lambda t=test_type: client.android_activity(scan_hash, t),
                                dynamic_dir / fname,
                                trace_dir,
                                f"dynamic_{fname.replace('.json', '')}",
                            )
                        except MobSFClientError as exc:
                            log(f"[WARN] Activity tester frida ({test_type}): {exc}")

                    # 7c. Monkey — случайные UI-события пока Frida hooks активны.
                    # Запускаем после activity tester, чтобы Frida перехватила API-вызовы,
                    # сгенерированные реальным UI-взаимодействием.
                    # Session daemon thread на MobSF сервере живёт 45s; monkey занимает
                    # monkey_events × monkey_throttle_ms ≈ 30s, что укладывается в окно.
                    frida_start = time.monotonic()
                    if package_name and self.config.monkey_events > 0:
                        monkey_timeout = (
                            self.config.monkey_events * self.config.monkey_throttle_ms / 1000 + 15
                        )
                        self._emit(
                            f"Monkey: {self.config.monkey_events} UI-событий "
                            f"({self.config.monkey_throttle_ms}ms между событиями)..."
                        )
                        try:
                            subprocess.run(
                                [
                                    "adb", "-s", emulator_id, "shell", "monkey",
                                    "-p", package_name,
                                    "--throttle", str(self.config.monkey_throttle_ms),
                                    "--pct-touch", "40",
                                    "--pct-motion", "30",
                                    "--pct-nav", "10",
                                    "--pct-majornav", "10",
                                    "--pct-syskeys", "5",
                                    "--pct-appswitch", "0",
                                    "--pct-anyevent", "5",
                                    "--ignore-crashes", "--ignore-timeouts",
                                    "--ignore-security-exceptions",
                                    str(self.config.monkey_events),
                                ],
                                capture_output=True,
                                timeout=monkey_timeout,
                            )
                        except Exception as exc:  # pylint: disable=broad-exception-caught
                            log(f"[WARN] monkey: {exc}")

                    # Ждём оставшееся время до конца 40s окна Frida
                    elapsed = time.monotonic() - frida_start
                    remaining = max(0.0, 40.0 - elapsed)
                    if remaining > 0:
                        self._emit(f"Ожидание Frida (ещё {remaining:.0f}s)...")
                        time.sleep(remaining)

                    for label, call, fname, trace_name in (
                        ("Сбор данных монитора API Frida",
                         lambda: client.frida_api_monitor(scan_hash),
                         "api_monitor.json", "dynamic_frida_api_monitor"),
                        ("Сбор журналов Frida",
                         lambda: client.frida_logs(scan_hash),
                         "logs.json", "dynamic_frida_logs"),
                        ("Сбор зависимостей приложения (Frida)",
                         lambda: client.frida_get_dependencies(scan_hash),
                         "dependencies.json", "dynamic_frida_dependencies"),
                    ):
                        try:
                            self._emit(f"{label}...")
                            self._call_and_save_json(
                                call, frida_dir / fname, trace_dir, trace_name,
                            )
                        except MobSFClientError as exc:
                            log(f"[WARN] {label}: {exc}")
                    artifacts["frida"] = self._relpath(run_dir, frida_dir)

            # Collect logcat before stopping via direct ADB (MobSF logcat API is SSE streaming)
            if package_name:
                self._emit("Сбор logcat...")
                logcat_path = dynamic_dir / "logcat.txt"
                self._collect_logcat_adb(emulator_id, package_name, logcat_path)
                if logcat_path.exists():
                    summary.logcat_lines = self._line_count(logcat_path)
                    artifacts["logcat"] = self._relpath(run_dir, logcat_path)

            # 8. Stop analysis (archives app data + collects logs server-side — can be slow)
            self._emit("Остановка динамического анализа...")
            try:
                self._call_and_save_json(
                    lambda: client.dynamic_stop_analysis(scan_hash),
                    dynamic_dir / "stop.json",
                    trace_dir,
                    "dynamic_stop",
                )
                summary.status = "stopped"
                artifacts["stop"] = self._relpath(run_dir, dynamic_dir / "stop.json")
            except MobSFClientError as exc:
                log(f"[WARN] dynamic_stop: {exc}")

            # 9. Fetch final report
            self._emit("Получение JSON-отчёта динамического анализа...")
            self._call_and_save_json(
                lambda: client.dynamic_report_json(scan_hash),
                dynamic_dir / "report.json",
                trace_dir,
                "dynamic_report_json",
            )
            artifacts["report_json"] = self._relpath(run_dir, dynamic_dir / "report.json")

            return summary, artifacts
        finally:
            if adb_bridge_proc is not None:
                try:
                    adb_bridge_proc.terminate()
                    adb_bridge_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    adb_bridge_proc.kill()
                    adb_bridge_proc.wait()
                except Exception:  # pylint: disable=broad-exception-caught
                    pass
            if mgr is not None:
                try:
                    mgr.stop()
                except Exception:  # pylint: disable=broad-exception-caught
                    pass

    def _check_mobsf_api_level(self, emulator_serial: str) -> None:
        """Raise MobSFClientError if the emulator API level exceeds MobSF's supported max (30)."""
        MOBSF_MAX_API = 30
        try:
            result = subprocess.run(
                ["adb", "-s", emulator_serial, "shell", "getprop", "ro.build.version.sdk"],
                capture_output=True, text=True, timeout=10,
            )
            api_str = result.stdout.strip()
            if api_str.isdigit() and int(api_str) > MOBSF_MAX_API:
                raise MobSFClientError(
                    f"MobSF динамический анализ не поддерживает API {api_str} "
                    f"(максимум API {MOBSF_MAX_API} / Android 11). "
                    f"Создайте AVD с API ≤ {MOBSF_MAX_API} или используйте MobSF ≥ 4.5."
                )
        except MobSFClientError:
            raise
        except Exception:  # pylint: disable=broad-exception-caught
            pass  # если adb недоступен, продолжаем — mobsfy сам упадёт с понятной ошибкой

    def _setup_adb_bridge(self, emulator_serial: str) -> "subprocess.Popen | None":
        """Enable ADB TCP mode and start socat bridge so Docker can reach the emulator.

        QEMU binds the emulator ADB port only on 127.0.0.1:5555. MobSF connects via
        host.docker.internal:5555 (= Docker bridge IP, e.g. 172.17.0.1). socat forwards
        bridge_ip:5555 → 127.0.0.1:5555 to bridge the gap.
        """
        from analysis.mobsf import MOBSF_CONTAINER_NAME  # noqa: PLC0415

        # Switch emulator adbd to TCP mode (idempotent)
        subprocess.run(
            ["adb", "-s", emulator_serial, "tcpip", "5555"],
            capture_output=True, timeout=15,
        )
        time.sleep(1)  # adbd restarts briefly

        # Get the IP that host.docker.internal resolves to inside the container
        insp = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}",
             MOBSF_CONTAINER_NAME],
            capture_output=True, text=True, timeout=10,
        )
        bridge_ip = insp.stdout.strip() or "172.17.0.1"

        try:
            proc = subprocess.Popen(
                ["socat",
                 f"TCP-LISTEN:5555,bind={bridge_ip},fork,reuseaddr",
                 "TCP:127.0.0.1:5555"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(0.5)
            self._emit(f"ADB bridge: {bridge_ip}:5555 → 127.0.0.1:5555 (pid={proc.pid})")
            return proc
        except FileNotFoundError:
            self._emit("[WARN] socat не найден — ADB bridge недоступен (apt-get install socat)")
            return None

    def _setup_cacerts_bindmount(self, serial: str, log: Callable[[str], None]) -> None:
        """Bind-mount /system/etc/security/cacerts over a tmpfs copy so MobSF can push its CA.

        On API 30 the root partition is RO (dm-verity). MobSF's install_mobsf_ca() pushes its
        CA cert into /system/etc/security/cacerts which fails with EROFS. Fix: copy the existing
        system certs into /data/local/tmp/cacerts and bind-mount that directory back over the
        system path, making it writable without touching the real partition.
        """
        adb = ["adb", "-s", serial]
        try:
            # Check writeability directly — most reliable across Android versions.
            # /proc/mounts shows the block device as source (not the tmpfs dir), so grep on
            # source path is unreliable. A write test is always correct.
            chk = subprocess.run(
                adb + ["shell",
                       "touch /system/etc/security/cacerts/.tapka_wtest >/dev/null 2>&1"
                       " && rm -f /system/etc/security/cacerts/.tapka_wtest && echo WRITABLE"
                       " || echo READONLY"],
                capture_output=True, text=True, timeout=10,
            )
            if "WRITABLE" in (chk.stdout or ""):
                log("cacerts bind-mount уже активен (/system/etc/security/cacerts writable)")
                return
            r = subprocess.run(
                adb + ["shell",
                       "mkdir -p /data/local/tmp/cacerts"
                       " && cp /system/etc/security/cacerts/* /data/local/tmp/cacerts/ >/dev/null 2>&1; "
                       "chmod 755 /data/local/tmp/cacerts"
                       " && mount --bind /data/local/tmp/cacerts /system/etc/security/cacerts"],
                capture_output=True, text=True, timeout=20,
            )
            if r.returncode == 0:
                log("cacerts bind-mount установлен (/system/etc/security/cacerts writable)")
            else:
                log(f"[WARN] cacerts bind-mount не удался: {r.stderr.strip() or r.stdout.strip()}")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"[WARN] cacerts bind-mount: {exc}")

    def _run_quark(
        self,
        apk_path: Path,
        quark_dir: Path,
        run_dir: Path,
        log: Callable[[str], None],
        ctx: RunContext | None = None,
    ) -> QuarkReport:
        if not self.config.enable_quark:
            report = QuarkReport(status="skipped")
            self._append_quark_error(report, "Анализ Quark отключён.")
            return report
        self._emit("Выполнение правил Quark...")
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
            log(f"Статус анализа Quark: {report.status}")
        return report


    def _build_report(
        self,
        base_url: str,
        started_at: str,
        static_summary: MobSFStaticSummary,
        dynamic_summary: MobSFDynamicAndroidSummary,
        ios_summary: MobSFIosSummary,
        artifacts: MobSFArtifacts,
    ) -> MobSFReport:
        instance = self._build_instance(base_url, started_at)
        features = self._build_feature_flags()
        return MobSFReport(
            instance=instance,
            features=features,
            artifacts=artifacts,
            static=static_summary,
            dynamic_android=dynamic_summary,
            ios=ios_summary,
        )

    def _build_error_report(self, started_at: str) -> MobSFReport:
        instance = self._build_instance(normalize_base_url(DEFAULT_MOBSF_URL), started_at)
        features = self._build_feature_flags()
        static_summary = MobSFStaticSummary()
        dynamic_summary = MobSFDynamicAndroidSummary(enabled=self.config.enable_dynamic_android)
        ios_summary = MobSFIosSummary(enabled=self.config.enable_ios, status="Не настроено")
        artifacts = MobSFArtifacts()
        return MobSFReport(
            instance=instance,
            features=features,
            artifacts=artifacts,
            static=static_summary,
            dynamic_android=dynamic_summary,
            ios=ios_summary,
        )

    def _build_instance(self, base_url: str, started_at: str) -> MobSFInstanceInfo:
        return MobSFInstanceInfo(
            base_url=base_url,
            started_at=started_at,
            finished_at=now_utc_iso(),
        )

    def _build_feature_flags(self) -> MobSFFeatureFlags:
        return MobSFFeatureFlags(
            enable_dynamic_android=self.config.enable_dynamic_android,
            enable_ios=self.config.enable_ios,
            cleanup_scans=self.config.cleanup_scans,
            download_pdf=self.config.download_pdf,
            view_source=self.config.view_source,
            frida_steps=self.config.frida_steps,
            tls_tests=self.config.tls_tests,
        )

    def _check_available(self, client: MobSFClient) -> None:
        try:
            response = client.scans(page=1, page_size=1)
        except requests.RequestException as exc:
            raise MobSFClientError(f"MobSF недоступен: {exc}") from exc
        if response.status_code >= 400:
            snippet = self._short_text(response.text)
            raise MobSFClientError(
                f"MobSF недоступен (HTTP {response.status_code}): {snippet}",
                response=response,
            )

    def _resolve_mobsf_settings(self) -> tuple[str, str]:
        settings = load_settings()
        mobsf = settings.get("mobsf", {})
        base_url = normalize_base_url(mobsf.get("url", DEFAULT_MOBSF_URL))
        api_key = os.environ.get("MOBSF_API_KEY") or get_mobsf_api_key()
        if not api_key:
            raise RuntimeError("API-ключ MobSF не настроен (MOBSF_API_KEY).")
        return base_url, api_key

    def _resolve_apk_display_name(self, project_id: str, apk_path: Path) -> str:
        try:
            project = self.storage.load_project(project_id)
        except (FileNotFoundError, ValueError, json.JSONDecodeError, OSError):
            return apk_path.name
        if project.apk_meta and project.apk_meta.name:
            return project.apk_meta.name
        return apk_path.name

    def _validate_upload_file(
        self, apk_path: Path, display_name: str, log: Callable[[str], None]
    ) -> None:
        supported_ext = {".apk", ".zip", ".ipa", ".appx"}
        ext = Path(display_name).suffix.lower()
        if ext not in supported_ext:
            raise RuntimeError(
                "MobSF поддерживает загрузку файлов .apk, .zip, .ipa и .appx. "
                f"Получен файл: {display_name}"
            )
        if not zipfile.is_zipfile(apk_path):
            raise RuntimeError(f"Файл не является корректным архивом: {apk_path}")
        size = apk_path.stat().st_size
        log(f"Загрузка {display_name} ({size} байт).")

    def _call_and_save_json(
        self,
        func: Callable[[], MobSFResponse],
        path: Path,
        trace_dir: Path,
        trace_name: str,
    ) -> MobSFResponse:
        return self._call_and_save_response(func, path, trace_dir, trace_name)

    def _call_and_save_text(
        self,
        func: Callable[[], MobSFResponse],
        path: Path,
        trace_dir: Path,
        trace_name: str,
    ) -> MobSFResponse:
        return self._call_and_save_response(func, path, trace_dir, trace_name)

    def _call_and_save_response(
        self,
        func: Callable[[], MobSFResponse],
        path: Path,
        trace_dir: Path,
        trace_name: str,
    ) -> MobSFResponse:
        try:
            response = func()
        except requests.RequestException as exc:
            self._write_trace(trace_dir, trace_name, 0, note=str(exc))
            raise MobSFClientError(f"Ошибка запроса к MobSF: {exc}") from exc
        self._write_trace(trace_dir, trace_name, response.status_code, response.text)
        self._write_text(path, response.text)
        if response.status_code >= 400:
            snippet = self._short_text(response.text)
            raise MobSFClientError(
                f"Ошибка API MobSF (HTTP {response.status_code}): {snippet}",
                response=response,
            )
        return response

    def _short_text(self, text: str | None, limit: int = 300) -> str:
        if not text:
            return "-"
        cleaned = " ".join(text.split())
        if len(cleaned) <= limit:
            return cleaned
        return cleaned[:limit] + "..."

    def _write_trace(
        self,
        trace_dir: Path,
        name: str,
        status_code: int,
        body: str | None = None,
        note: str | None = None,
    ) -> None:
        payload = {"status": status_code}
        if note:
            payload["note"] = note
        if body is not None:
            payload["body"] = body
        trace_path = trace_dir / f"{name}.json"
        trace_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _write_text(self, path: Path, text: str | None) -> None:
        path.write_text(text or "", encoding="utf-8")

    def _write_binary(self, path: Path, content: bytes) -> None:
        path.write_bytes(content)

    def _emit(self, message: str) -> None:
        emit_progress(self.on_progress, message)

    def _append_quark_error(self, report: QuarkReport, message: str) -> None:
        errors = report.errors if isinstance(report.errors, list) else []
        errors = [str(item) for item in errors]
        errors.append(message)
        report.errors = errors

    def _emit_scan_status(self, status: str) -> None:
        if not self.on_progress:
            return
        self.on_progress(f"MOBSF_SCAN_STATUS:{status}")

    def _line_count(self, path: Path) -> int | None:
        if not path.exists():
            return None
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return sum(1 for _ in fh)

    def _scan_status_from_logs(self, payload: object) -> str | None:
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                return None
        if not isinstance(payload, dict):
            return None
        logs = payload.get("logs")
        if not isinstance(logs, list):
            return None
        for entry in reversed(logs):
            if isinstance(entry, dict):
                status = entry.get("status")
                if isinstance(status, str) and status.strip():
                    return status.strip()
        return None

    def _parse_appsec_findings(
        self,
        items: object,
        severity: str,
    ) -> list[MobSFAppSecFinding]:
        if not isinstance(items, list):
            return []
        findings = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            title = entry.get("title")
            if not isinstance(title, str):
                continue
            description = entry.get("description")
            if description is not None and not isinstance(description, str):
                description = str(description)
            section = entry.get("section")
            if section is not None and not isinstance(section, str):
                section = str(section)
            findings.append(
                MobSFAppSecFinding(
                    title=title,
                    description=description,
                    section=section,
                    severity=severity,
                )
            )
        return findings

    def _extract_static_summary(
        self,
        report_json: dict | list | None,
        summary: MobSFStaticSummary,
    ) -> MobSFStaticSummary:
        if isinstance(report_json, dict):
            summary.app_name = report_json.get("app_name") or summary.app_name
            summary.package_name = report_json.get("package_name") or summary.package_name
            summary.version_name = report_json.get("version_name") or summary.version_name
            version_code = report_json.get("version_code")
            if version_code is not None:
                summary.version_code = str(version_code)
            min_sdk = report_json.get("min_sdk")
            if min_sdk is not None:
                summary.min_sdk = str(min_sdk)
            target_sdk = report_json.get("target_sdk")
            if target_sdk is not None:
                summary.target_sdk = str(target_sdk)

            findings = report_json.get("findings")
            if isinstance(findings, list):
                summary.findings_total = len(findings)
            issues = report_json.get("issues")
            if isinstance(issues, dict):
                summary.issues = {str(k): int(v) for k, v in issues.items() if isinstance(v, int)}
            permissions = report_json.get("permissions")
            if isinstance(permissions, dict):
                permission_list = list(permissions.keys())
                summary.permissions_total = len(permission_list)
                summary.permissions_top = permission_list[:10]

            exported = report_json.get("exported_activities")
            if isinstance(exported, list):
                summary.exported_total = len(exported)
                summary.exported_top = exported[:10]
            elif isinstance(report_json.get("exported_count"), int):
                summary.exported_total = int(report_json["exported_count"])

            urls = report_json.get("urls")
            if isinstance(urls, list):
                url_values: list[str] = []
                seen: set[str] = set()
                for entry in urls:
                    if isinstance(entry, dict):
                        entries = entry.get("urls")
                        if isinstance(entries, list):
                            for value in entries:
                                if isinstance(value, str) and value not in seen:
                                    seen.add(value)
                                    url_values.append(value)
                    elif isinstance(entry, str) and entry not in seen:
                        seen.add(entry)
                        url_values.append(entry)
                summary.urls_total = len(seen) if seen else len(urls)
                summary.urls_top = url_values[:10]

            domains = report_json.get("domains")
            if isinstance(domains, dict):
                domain_list = list(domains.keys())
                summary.domains_total = len(domain_list)
                summary.domains_top = domain_list[:10]

            trackers = report_json.get("trackers")
            if isinstance(trackers, dict):
                detected = trackers.get("detected_trackers")
                total = trackers.get("total_trackers")
                items = trackers.get("trackers")
                if isinstance(detected, int):
                    summary.trackers_detected = detected
                if isinstance(total, int):
                    summary.trackers_total = total
                if isinstance(items, list):
                    tracker_list = [item for item in items if isinstance(item, str)]
                    summary.trackers_top = tracker_list[:10]

            secrets = report_json.get("secrets")
            if isinstance(secrets, list):
                summary.secrets_total = len(secrets)

            appsec = report_json.get("appsec")
            if isinstance(appsec, dict):
                score = appsec.get("security_score")
                if isinstance(score, (int, float)):
                    summary.security_score = int(score)
                appsec_summary: dict[str, int] = {}
                crypto_total = 0
                for key in ("high", "warning", "info", "secure", "hotspot"):
                    items = appsec.get(key)
                    if isinstance(items, list):
                        appsec_summary[key] = len(items)
                        for entry in items:
                            if isinstance(entry, dict) and entry.get("section") == "crypto":
                                crypto_total += 1
                summary.appsec_summary = appsec_summary
                summary.crypto_total = crypto_total or summary.crypto_total
                summary.appsec_high = self._parse_appsec_findings(appsec.get("high"), "high")
                summary.appsec_warning = self._parse_appsec_findings(appsec.get("warning"), "warning")
                summary.appsec_info = self._parse_appsec_findings(appsec.get("info"), "info")
                summary.appsec_secure = self._parse_appsec_findings(appsec.get("secure"), "secure")
                summary.appsec_hotspot = self._parse_appsec_findings(appsec.get("hotspot"), "hotspot")
                if isinstance(appsec.get("total_trackers"), int):
                    summary.trackers_total = appsec.get("total_trackers")
                if isinstance(appsec.get("trackers"), int):
                    summary.trackers_detected = appsec.get("trackers")

            manifest_summary = report_json.get("manifest_analysis", {}).get("manifest_summary")
            if isinstance(manifest_summary, dict):
                summary.manifest_summary = {
                    str(k): int(v) for k, v in manifest_summary.items() if isinstance(v, int)
                }

            code_summary = report_json.get("code_analysis", {}).get("summary")
            if isinstance(code_summary, dict):
                summary.code_summary = {str(k): int(v) for k, v in code_summary.items() if isinstance(v, int)}

            top_sections: dict[str, list[str]] = {}
            if summary.permissions_top:
                top_sections["permissions"] = summary.permissions_top
            if summary.exported_top:
                top_sections["exported_activities"] = summary.exported_top
            if summary.urls_top:
                top_sections["urls"] = summary.urls_top
            if summary.domains_top:
                top_sections["domains"] = summary.domains_top
            if summary.trackers_top:
                top_sections["trackers"] = summary.trackers_top
            summary.top_sections = top_sections
        return summary

    def _safe_name(self, value: str) -> str:
        return "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in value).strip("_")

    def _relpath(self, run_dir: Path, path: Path) -> str:
        try:
            return str(path.relative_to(run_dir))
        except ValueError:
            return str(path)
