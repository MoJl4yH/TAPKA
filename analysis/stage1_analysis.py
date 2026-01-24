import json
import re
import shutil
import time
import traceback
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, TextIO
import xml.etree.ElementTree as ET

from analysis.runner import run_command
from analysis.reporting import ReportManager
from analysis.stages import STAGE_STATIC
from analysis.severity import SeverityEngine
from analysis.storage import Storage
from models import Run, Finding, CommandResult


@dataclass(frozen=True)
class FindingSpec:
    category: str
    evidence: str
    file_path: str = ""
    line: int | None = None
    column: int | None = None
    confidence: str = "C1"
    evidence_type: str = "string"
    tags: set[str] = field(default_factory=set)
    sources: list[str] = field(default_factory=list)
    source: str | None = None


@dataclass(frozen=True)
class Stage1Paths:
    run_dir: Path
    logs_dir: Path
    artifacts_dir: Path
    apktool_dir: Path
    jadx_dir: Path
    certs_dir: Path


@dataclass
class ProgressTracker:
    runner: "Stage1StaticRunner"
    log: Callable[[str], None]
    total_steps: int
    overall_start: float
    current_message: str = "Preparing Stage 1"
    completed_steps: int = 0
    step_durations: list[float] = field(default_factory=list)

    def estimate_eta(self) -> int | None:
        if not self.step_durations or self.total_steps <= self.completed_steps:
            return None
        avg = sum(self.step_durations) / len(self.step_durations)
        remaining = self.total_steps - self.completed_steps
        return max(0, int(avg * remaining))

    def emit(self) -> None:
        elapsed = time.monotonic() - self.overall_start
        self.runner._emit_progress(
            self.current_message,
            self.completed_steps,
            self.total_steps,
            elapsed,
            self.estimate_eta(),
        )

    def update_total_steps(self, new_total: int, message: str) -> None:
        self.total_steps = new_total
        self.current_message = message
        self.emit()

    def run_step(self, label: str, func):
        self.current_message = f"Running: {label}"
        self.log(self.current_message)
        self.emit()
        step_start = time.monotonic()
        result = func()
        self.step_durations.append(time.monotonic() - step_start)
        self.completed_steps += 1
        self.emit()
        return result


@dataclass
class PipelineState:
    cert_names: list[str]
    so_count_estimate: int
    rg_step_count: int
    progress: ProgressTracker


class Stage1StaticRunner:
    REQUIRED_TOOLS = [
        "file",
        "stat",
        "sha256sum",
        "apksigner",
        "aapt2",
        "unzip",
        "grep",
        "keytool",
        "apktool",
        "jadx",
        "rg",
        "strings",
        "yara",
    ]
    CERT_LIST_PATTERN = r"META-INF/.*\.(RSA|DSA|EC)$"
    JADX_PARTIAL_PATTERN = re.compile(r"finished with errors", re.IGNORECASE)
    APKTOOL_FLEX_PATTERN = re.compile(r"flex scanner failed", re.IGNORECASE)
    RG_PATTERN_SPECS = [
        {
            "category": "secret_endpoints_hardcoded",
            "pattern": r'(https?|wss?|ftp|grpc|grpcs|mqtts?|rtsp)://(?!schemas\.android\.com)[^" <>{}]{8,}',
            "targets": ("apktool", "jadx"),
            "confidence": "C1",
            "evidence_type": "string",
            "tags": {"network"},
            "source": "endpoint_url",
        },
        {
            "category": "secret_endpoints_hardcoded",
            "pattern": r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
            "targets": ("apktool", "jadx"),
            "confidence": "C1",
            "evidence_type": "string",
            "tags": {"network"},
            "source": "endpoint_ipv4",
        },
        {
            "category": "secret_sensitive_kv",
            "pattern": r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|auth[_-]?token|access[_-]?token|private[_-]?key)\b\s*[:=>]\s*[\"'][A-Za-z0-9+/=_\-.]{8,}[\"']",
            "targets": ("apktool", "jadx"),
            "confidence": "C1",
            "evidence_type": "string",
            "tags": set(),
            "source": "secret_kv",
        },
        {
            "category": "secret_jwt_embedded",
            "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "targets": ("apktool", "jadx"),
            "confidence": "C1",
            "evidence_type": "string",
            "tags": set(),
            "source": "jwt",
        },
        {
            "category": "secret_private_key_pem",
            "pattern": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
            "targets": ("apktool", "jadx"),
            "confidence": "C1",
            "evidence_type": "string",
            "tags": set(),
            "source": "private_key_pem",
        },
        {
            "category": "ndv_dynamic_code_loading",
            "pattern": r"DexClassLoader|InMemoryDexClassLoader|PathClassLoader|loadDex|defineClass|Runtime\.exec|ProcessBuilder|System\.loadLibrary|System\.load",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"dynamic_code"},
            "source": "dynamic_code_loader",
        },
        {
            "category": "sec_insecure_webview_bridge",
            "pattern": r"addJavascriptInterface",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "webview_js_bridge",
        },
        {
            "category": "sec_insecure_webview_file_access",
            "pattern": r"setAllowFileAccess|setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "webview_file_access",
        },
        {
            "category": "sec_tls_trust_all",
            "pattern": r"X509TrustManager|checkServerTrusted",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"mitm_enabler"},
            "source": "tls_trust_all",
        },
        {
            "category": "sec_hostname_verifier_bypass",
            "pattern": r"HostnameVerifier",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"mitm_enabler"},
            "source": "hostname_verifier",
        },
        {
            "category": "sec_custom_ca_store_or_user_certs",
            "pattern": r"KeyStore\.getInstance\(\"(BKS|PKCS12|JKS)\"\)|setCertificateEntry|CertificateFactory\.getInstance",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "custom_ca_store",
        },
        {
            "category": "sec_proxy_setting_modification",
            "pattern": r"settings\s+put\s+global\s+http_proxy",
            "targets": ("jadx", "apktool"),
            "confidence": "C1",
            "evidence_type": "string",
            "tags": set(),
            "source": "proxy_setting",
        },
        {
            "category": "vul_pendingintent_mutable",
            "pattern": r"FLAG_MUTABLE|PendingIntent\.FLAG_MUTABLE",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "pendingintent_mutable",
        },
        {
            "category": "ndv_clipboard_monitoring",
            "pattern": r"ClipboardManager|getPrimaryClip|addPrimaryClipChangedListener",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "clipboard_monitor",
        },
        {
            "category": "ndv_notification_listener",
            "pattern": r"NotificationListenerService",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "notification_listener",
        },
        {
            "category": "ndv_overlay_abuse",
            "pattern": r"TYPE_APPLICATION_OVERLAY",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "overlay_type",
        },
        {
            "category": "ndv_screen_capture_mediaprojection",
            "pattern": r"MediaProjectionManager|MediaProjection|createVirtualDisplay|ImageReader",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"background"},
            "source": "mediaprojection",
        },
        {
            "category": "ndv_accessibility_surveillance",
            "pattern": r"AccessibilityService|getRootInActiveWindow|AccessibilityEvent",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"background"},
            "source": "accessibility",
        },
        {
            "category": "ndv_keylogging_like",
            "pattern": r"TYPE_VIEW_TEXT_CHANGED|TYPE_WINDOW_CONTENT_CHANGED",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"background"},
            "source": "accessibility_text",
        },
        {
            "category": "ndv_mic_eavesdropping",
            "pattern": r"AudioRecord|MediaRecorder|AudioSource\.MIC|AudioSource\.VOICE_CALL|AudioSource\.VOICE_COMMUNICATION",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "mic_record",
        },
        {
            "category": "ndv_camera_surveillance",
            "pattern": r"android\.hardware\.camera2|android\.hardware\.Camera",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "camera_api",
        },
        {
            "category": "ndv_geo_tracking_foreground",
            "pattern": r"android\.location\.LocationManager|FusedLocationProviderClient|getLastLocation|requestLocationUpdates",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "location_api",
        },
        {
            "category": "ndv_traffic_intercept_vpn",
            "pattern": r"android\.net\.VpnService|VpnService\$Builder|establish\(",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"network"},
            "source": "vpn_service",
        },
        {
            "category": "persist_workmanager_periodic",
            "pattern": r"WorkManager|PeriodicWorkRequest",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"persistence", "background"},
            "source": "workmanager",
        },
        {
            "category": "persist_jobscheduler_periodic",
            "pattern": r"JobScheduler|setPeriodic",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"persistence", "background"},
            "source": "jobscheduler",
        },
        {
            "category": "persist_alarmmanager_repeating",
            "pattern": r"AlarmManager|setRepeating|setInexactRepeating",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"persistence", "background"},
            "source": "alarmmanager",
        },
        {
            "category": "anomaly_frida_xposed_magisk_detection",
            "pattern": r"(?i)\b(emulator|goldfish|ranchu|genymotion|frida|xposed|substrate|magisk|busybox)\b",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "analysis_evasion",
        },
        {
            "category": "anomaly_anti_debug",
            "pattern": r"(?i)(?:/system/(?:bin|xbin)/su\b|\bBuild\.(?:FINGERPRINT|MODEL)\b|\bDebug\.isDebuggerConnected\b|\bTracerPid\b)",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "analysis_evasion",
        },
    ]
    STRINGS_PATTERN_STRINGS = {
        "secret_endpoints_hardcoded": r'(https?|wss?|ftp|grpc|grpcs|mqtts?|rtsp)://(?!schemas\.android\.com)[^" <>{}]{8,}',
        "secret_endpoints_ipv4": r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
        "ndv_dynamic_code_loading": r"DexClassLoader|InMemoryDexClassLoader|PathClassLoader",
        "ndv_remote_command": r"Runtime\.exec|ProcessBuilder",
    }
    STRINGS_CATEGORY_META = {
        "secret_endpoints_hardcoded": {"tags": {"network"}, "category": "secret_endpoints_hardcoded"},
        "secret_endpoints_ipv4": {"tags": {"network"}, "category": "secret_endpoints_hardcoded"},
        "ndv_dynamic_code_loading": {"tags": {"dynamic_code"}, "category": "ndv_dynamic_code_loading"},
        "ndv_remote_command": {"tags": set(), "category": "ndv_remote_command"},
    }
    YARA_RULE_CATEGORY = {
        "ANDROID_Remote_Command_MQTT_WS": ("ndv_remote_command", {"network"}),
        "ANDROID_Remote_Command_FCM": ("ndv_remote_command", {"network"}),
        "ANDROID_Geo_Tracking_Location_APIs": ("ndv_geo_tracking_foreground", set()),
        "ANDROID_Geo_Tracking_Persistence": ("ndv_geo_tracking_background", {"persistence", "background"}),
        "ANDROID_Eavesdropping_Microphone": ("ndv_mic_eavesdropping", set()),
        "ANDROID_Camera_Surveillance": ("ndv_camera_surveillance", set()),
        "ANDROID_Screen_Capture_MediaProjection": ("ndv_screen_capture_mediaprojection", {"background"}),
        "ANDROID_Accessibility_Screen_Observation": ("ndv_accessibility_surveillance", {"background"}),
        "ANDROID_Traffic_Interception_VPN_TUN": ("ndv_traffic_intercept_vpn", {"network"}),
        "ANDROID_TLS_TrustAll_or_MITM_Indicators": ("sec_tls_trust_all", {"mitm_enabler"}),
        "ANDROID_Combined_Spy_Profile_Strong": ("ndv_remote_command", {"network", "persistence", "background"}),
    }

    def __init__(
        self,
        storage: Storage,
        timeout_sec: int = 600,
        on_progress=None,
        yara_rules_path: str | None = None,
    ):
        self.storage = storage
        self.timeout_sec = timeout_sec
        self.on_progress = on_progress
        self._run_dir: Path | None = None
        if yara_rules_path:
            self.yara_rules_path = Path(yara_rules_path).expanduser()
        else:
            self.yara_rules_path = (
                Path(__file__).resolve().parent / "yara" / "android_spy_triage.yar"
            )

    def _build_paths(self, run_dir: Path) -> Stage1Paths:
        artifacts_dir = run_dir / "artifacts"
        return Stage1Paths(
            run_dir=run_dir,
            logs_dir=run_dir / "logs",
            artifacts_dir=artifacts_dir,
            apktool_dir=artifacts_dir / "out_apktool",
            jadx_dir=artifacts_dir / "out_jadx",
            certs_dir=artifacts_dir / "certs",
        )

    def _build_logger(self, log_path: Path) -> Callable[[str], None]:
        def log(message: str) -> None:
            timestamp = datetime.now().isoformat(timespec="seconds")
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(f"{timestamp} {message}\n")

        return log

    def _prepare_run(self, run: Run, run_dir: Path, log: Callable[[str], None]) -> None:
        missing = self._check_tools()
        run.tools_checked = list(self.REQUIRED_TOOLS)
        run.tools_missing = missing
        if not missing:
            return
        error = f"Missing required tools: {', '.join(missing)}"
        log(error)
        run.errors.append(error)
        run.status = "Error"
        run.finished_at = datetime.now().isoformat(timespec="seconds")
        self.storage.save_run(run, run_dir)
        raise RuntimeError(error)

    def _init_progress(
        self,
        apk_path: Path,
        paths: Stage1Paths,
        log: Callable[[str], None],
    ) -> PipelineState:
        cert_names = self._list_cert_entries(apk_path)
        so_count_estimate = self._count_zip_entries(apk_path, ".so")
        rg_step_count = self._rg_step_count(paths.apktool_dir.exists(), paths.jadx_dir.exists())
        total_steps = 12 + len(cert_names) + rg_step_count + so_count_estimate
        progress = ProgressTracker(
            runner=self,
            log=log,
            total_steps=total_steps,
            overall_start=time.monotonic(),
        )
        progress.emit()
        return PipelineState(
            cert_names=cert_names,
            so_count_estimate=so_count_estimate,
            rg_step_count=rg_step_count,
            progress=progress,
        )

    def _run_core_tools(
        self,
        apk_path: Path,
        logs_dir: Path,
        progress: ProgressTracker,
    ) -> list[CommandResult]:
        tasks = [
            ("File type (file)", "file", ["file", str(apk_path)], "file"),
            ("File stat (stat)", "stat", ["stat", str(apk_path)], "stat"),
            ("Checksum (sha256sum)", "sha256sum", ["sha256sum", str(apk_path)], "sha256sum"),
            (
                "APK signature (apksigner)",
                "apksigner",
                ["apksigner", "verify", "--verbose", "--print-certs", str(apk_path)],
                "apksigner",
            ),
            ("APK manifest (aapt2)", "aapt2", ["aapt2", "dump", "badging", str(apk_path)], "aapt2"),
        ]
        results = []
        for label, tool, argv, log_label in tasks:
            results.append(
                progress.run_step(
                    label,
                    lambda tool=tool, argv=argv, log_label=log_label: self._run_tool(
                        tool,
                        argv,
                        logs_dir,
                        log_label,
                    ),
                )
            )
        return results

    def _run_cert_steps(
        self,
        apk_path: Path,
        paths: Stage1Paths,
        state: PipelineState,
        log: Callable[[str], None],
    ) -> list[CommandResult]:
        results: list[CommandResult] = []
        unzip_result = state.progress.run_step(
            "List APK entries (unzip)",
            lambda: self._run_tool(
                "unzip",
                ["unzip", "-l", str(apk_path)],
                paths.logs_dir,
                "unzip_list",
            ),
        )
        results.append(unzip_result)
        cert_list_result = state.progress.run_step(
            "Filter META-INF certs (grep)",
            lambda: self._run_tool(
                "grep",
                ["grep", "-E", self.CERT_LIST_PATTERN, str(Path(unzip_result.stdout_path))],
                paths.logs_dir,
                "certs_list",
            ),
        )
        results.append(cert_list_result)
        listed_certs = self._parse_cert_listing(Path(cert_list_result.stdout_path))
        state.cert_names = self._update_cert_names(listed_certs, state.cert_names, state.progress)
        cert_count = len(state.cert_names)

        extracted_certs = state.progress.run_step(
            "Extract META-INF certs",
            lambda: self._extract_certs(apk_path, paths.certs_dir, log, state.cert_names),
        )
        self._update_step_estimate(
            "cert count",
            cert_count,
            len(extracted_certs),
            state.progress,
        )
        for index, cert_path in enumerate(extracted_certs, start=1):
            results.append(
                state.progress.run_step(
                    f"Cert details ({index}/{len(extracted_certs)})",
                    lambda cert_path=cert_path, index=index: self._run_tool(
                        "keytool",
                        ["keytool", "-printcert", "-file", str(cert_path)],
                        paths.logs_dir,
                        f"keytool_{index}",
                    ),
                )
            )
        return results

    def _run_decompile_steps(
        self,
        apk_path: Path,
        paths: Stage1Paths,
        state: PipelineState,
    ) -> list[CommandResult]:
        results = []
        if paths.apktool_dir.exists():
            shutil.rmtree(paths.apktool_dir, ignore_errors=True)
        apktool_result = state.progress.run_step(
            "Decode resources (apktool)",
            lambda: self._run_tool(
                "apktool",
                ["apktool", "d", "-f", "-o", str(paths.apktool_dir), str(apk_path)],
                paths.logs_dir,
                "apktool",
            ),
        )
        if self._log_contains(apktool_result, self.APKTOOL_FLEX_PATTERN):
            if paths.apktool_dir.exists():
                shutil.rmtree(paths.apktool_dir, ignore_errors=True)
            apktool_result = self._run_tool(
                "apktool",
                ["apktool", "d", "-f", "-r", "-o", str(paths.apktool_dir), str(apk_path)],
                paths.logs_dir,
                "apktool_nores",
            )
        results.append(apktool_result)
        results.append(
            state.progress.run_step(
                "Decompile code (jadx)",
                lambda: self._run_tool(
                    "jadx",
                    ["jadx", "-d", str(paths.jadx_dir), str(apk_path)],
                    paths.logs_dir,
                    "jadx",
                ),
            )
        )
        return results

    def _update_scan_estimates(self, paths: Stage1Paths, state: PipelineState) -> list[Path]:
        state.rg_step_count = self._update_step_estimate(
            "rg steps",
            state.rg_step_count,
            self._rg_step_count(paths.apktool_dir.exists(), paths.jadx_dir.exists()),
            state.progress,
        )
        so_files = list(paths.apktool_dir.rglob("*.so"))
        state.so_count_estimate = self._update_step_estimate(
            "strings targets",
            state.so_count_estimate,
            len(so_files),
            state.progress,
        )
        return so_files

    def _update_cert_names(
        self,
        listed_certs: list[str],
        cert_names: list[str],
        progress: ProgressTracker,
    ) -> list[str]:
        if not listed_certs:
            return cert_names
        if len(listed_certs) != len(cert_names):
            delta = len(listed_certs) - len(cert_names)
            progress.update_total_steps(
                progress.total_steps + delta,
                f"Updated cert count: {len(listed_certs)}",
            )
        return listed_certs

    def _update_step_estimate(
        self,
        label: str,
        previous_count: int,
        current_count: int,
        progress: ProgressTracker,
    ) -> int:
        if current_count != previous_count:
            delta = current_count - previous_count
            progress.update_total_steps(
                progress.total_steps + delta,
                f"Updated {label}: {current_count}",
            )
        return current_count

    def _run_pipeline(
        self,
        run: Run,
        paths: Stage1Paths,
        log: Callable[[str], None],
    ) -> tuple[list[Finding], list[CommandResult], ProgressTracker]:
        apk_path = Path(run.apk_path)
        state = self._init_progress(apk_path, paths, log)
        command_results: list[CommandResult] = []
        command_results.extend(self._run_core_tools(apk_path, paths.logs_dir, state.progress))
        command_results.extend(self._run_cert_steps(apk_path, paths, state, log))
        command_results.extend(self._run_decompile_steps(apk_path, paths, state))
        so_files = self._update_scan_estimates(paths, state)

        findings, finding_results = self._collect_findings(
            apktool_dir=paths.apktool_dir,
            jadx_dir=paths.jadx_dir,
            logs_dir=paths.logs_dir,
            run_dir=paths.run_dir,
            run_step=state.progress.run_step,
            so_files=so_files,
        )
        command_results.extend(finding_results)
        yara_result = state.progress.run_step(
            "YARA scan",
            lambda: self._run_yara(paths.logs_dir, paths.apktool_dir, paths.jadx_dir, apk_path),
        )
        command_results.append(yara_result)
        findings.extend(self._yara_findings(paths.logs_dir, paths.run_dir))
        findings = self._post_process_findings(findings, paths.run_dir)
        SeverityEngine.apply(findings)

        return findings, command_results, state.progress

    def run(self, project_id: str) -> Run:
        run, run_dir = self.storage.create_run(project_id, STAGE_STATIC)
        self._run_dir = run_dir
        paths = self._build_paths(run_dir)
        log = self._build_logger(paths.logs_dir / "runner.log")
        self._prepare_run(run, run_dir, log)

        # Broad catch ensures run status and logs are updated even on unexpected failures.
        try:
            findings, command_results, progress = self._run_pipeline(run, paths, log)
            self._apply_result_statuses(run, command_results)

            run.command_results = command_results
            findings_path = self.storage.save_findings(run_dir, findings)
            run.findings_path = str(findings_path)
            run.status = "Done"
            run.finished_at = datetime.now().isoformat(timespec="seconds")

            report_manager = ReportManager(self.storage)
            _, html_path = progress.run_step(
                "Generate reports",
                lambda: report_manager.generate_stage1(run, run_dir, findings),
            )
            run.report_path = str(html_path)
            report_manager.ensure_stub_reports(run, run_dir)

            self.storage.save_run(run, run_dir)
            progress.current_message = "Done"
            progress.emit()
            log("Stage 1 complete.")
            return run
        except Exception as exc:  # pylint: disable=broad-exception-caught
            run.status = "Error"
            run.finished_at = datetime.now().isoformat(timespec="seconds")
            run.errors.append(f"Stage 1 failed: {exc}")
            log(traceback.format_exc())
            self.storage.save_run(run, run_dir)
            log(f"Stage 1 failed: {exc}")
            raise

    def _check_tools(self) -> list[str]:
        missing = []
        for tool in self.REQUIRED_TOOLS:
            if shutil.which(tool) is None:
                missing.append(tool)
        return missing

    def _apply_result_statuses(self, run: Run, command_results: list[CommandResult]) -> None:
        for result in command_results:
            result.status = self._classify_result(result)
            if result.status != "fail":
                continue
            if result.timed_out:
                run.errors.append(f"{result.tool} timed out")
            elif result.error:
                run.errors.append(f"{result.tool} failed: {result.error}")
            else:
                run.errors.append(f"{result.tool} returned code {result.return_code}")

    def _classify_result(self, result: CommandResult) -> str:
        if result.timed_out or result.error:
            return "fail"
        if result.tool == "jadx" and self._is_jadx_partial(result):
            return "partial"
        allowed = {0, None}
        if result.tool in ("rg", "grep"):
            allowed.add(1)
        if result.return_code in allowed:
            return "success"
        return "fail"

    def _is_jadx_partial(self, result: CommandResult) -> bool:
        return self._log_contains(result, self.JADX_PARTIAL_PATTERN)

    def _log_contains(self, result: CommandResult, pattern: re.Pattern) -> bool:
        for path_str in (result.stdout_path, result.stderr_path):
            try:
                path = Path(path_str)
                if not path.exists():
                    continue
                if pattern.search(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except (OSError, UnicodeError):
                continue
        return False

    def _rg_step_count(self, apktool_exists: bool, jadx_exists: bool) -> int:
        targets = set()
        if apktool_exists:
            targets.add("apktool")
        if jadx_exists:
            targets.add("jadx")
        return sum(
            1
            for spec in self.RG_PATTERN_SPECS
            for target in spec["targets"]
            if target in targets
        )

    def _run_tool(
        self,
        tool: str,
        argv: list[str],
        logs_dir: Path,
        label: str,
    ):
        stdout_path = logs_dir / f"{label}.stdout.txt"
        stderr_path = logs_dir / f"{label}.stderr.txt"
        return run_command(
            tool=tool,
            argv=argv,
            cwd=str(logs_dir.parent),
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            timeout=self.timeout_sec,
        )

    def _run_yara(
        self,
        logs_dir: Path,
        apktool_dir: Path,
        jadx_dir: Path,
        apk_path: Path,
    ) -> CommandResult:
        rules_path = self.yara_rules_path
        _ = apk_path
        stdout_path = logs_dir / "yara.stdout.txt"
        stderr_path = logs_dir / "yara.stderr.txt"
        argv = ["yara", "-r", "-s", str(rules_path)]
        if not rules_path or not rules_path.is_file():
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text(
                f"YARA rules not found: {rules_path}\n",
                encoding="utf-8",
            )
            return CommandResult(
                tool="yara",
                argv=argv,
                cwd=str(logs_dir.parent),
                return_code=None,
                duration_sec=0.0,
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
                error="rules_not_found",
            )
        targets = []
        for path in (apktool_dir, jadx_dir):
            if path.exists():
                targets.append(str(path))
        if not targets:
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            return CommandResult(
                tool="yara",
                argv=argv,
                cwd=str(logs_dir.parent),
                return_code=0,
                duration_sec=0.0,
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
            )
        argv.extend(targets)
        return self._run_tool("yara", argv, logs_dir, "yara")

    def _write_yara_scan_list(
        self,
        list_path: Path,
        apktool_dir: Path,
        jadx_dir: Path,
        apk_path: Path,
    ) -> None:
        list_path.parent.mkdir(parents=True, exist_ok=True)
        with list_path.open("w", encoding="utf-8") as handle:
            for base_dir in (apktool_dir, jadx_dir):
                if not base_dir.exists():
                    continue
                for file_path in base_dir.rglob("*"):
                    if file_path.is_file():
                        handle.write(f"{file_path}\n")
            if apk_path.exists():
                handle.write(f"{apk_path}\n")

    def _extract_certs(
        self,
        apk_path: Path,
        certs_dir: Path,
        log,
        cert_names: list[str] | None = None,
    ) -> list[Path]:
        certs_dir.mkdir(parents=True, exist_ok=True)
        extracted = []
        try:
            with zipfile.ZipFile(apk_path, "r") as handle:
                names = cert_names or handle.namelist()
                for name in names:
                    if not name.upper().startswith("META-INF/"):
                        continue
                    if not name.upper().endswith((".RSA", ".DSA", ".EC")):
                        continue
                    target = certs_dir / Path(name).name
                    with handle.open(name) as source, target.open("wb") as dest:
                        dest.write(source.read())
                    extracted.append(target)
        except (OSError, zipfile.BadZipFile, KeyError) as exc:
            log(f"Failed to extract certs: {exc}")
        return extracted

    def _collect_findings(
        self,
        apktool_dir: Path,
        jadx_dir: Path,
        logs_dir: Path,
        run_dir: Path,
        run_step,
        so_files: list[Path],
    ) -> tuple[list[Finding], list[CommandResult]]:
        findings: list[Finding] = []
        command_results = []
        manifest_findings, manifest_meta = self._manifest_findings(apktool_dir, run_dir, logs_dir)
        findings.extend(manifest_findings)
        findings.extend(self._apksigner_findings(logs_dir, run_dir, manifest_meta.get("target_sdk")))
        findings.extend(self._keytool_findings(logs_dir, run_dir))
        rg_targets = {}
        if apktool_dir.exists():
            rg_targets["apktool"] = apktool_dir
        if jadx_dir.exists():
            rg_targets["jadx"] = jadx_dir

        for label, target in rg_targets.items():
            for spec in self.RG_PATTERN_SPECS:
                if label not in spec["targets"]:
                    continue
                rg_findings, result = self._rg_findings(
                    spec=spec,
                    target=target,
                    logs_dir=logs_dir,
                    run_dir=run_dir,
                    source=f"rg_{label}",
                    run_step=run_step,
                )
                findings.extend(rg_findings)
                command_results.append(result)

        if apktool_dir.exists():
            patterns = {
                category: re.compile(pattern)
                for category, pattern in self.STRINGS_PATTERN_STRINGS.items()
            }
            strings_findings, string_results = self._strings_findings(
                so_files=so_files,
                logs_dir=logs_dir,
                patterns=patterns,
                run_dir=run_dir,
                run_step=run_step,
            )
            findings.extend(strings_findings)
            command_results.extend(string_results)

        findings.extend(self._obfuscation_findings(jadx_dir, run_dir))
        return findings, command_results

    def _rg_findings(
        self,
        spec: dict,
        target: Path,
        logs_dir: Path,
        run_dir: Path,
        source: str,
        run_step,
    ) -> tuple[list[Finding], CommandResult]:
        category = spec["category"]
        pattern = spec["pattern"]
        label = f"rg_{category}_{source}"
        progress_label = f"RG {category} ({source.replace('rg_', '')})"
        result = run_step(
            progress_label,
            lambda: self._run_tool(
                "rg",
                ["rg", "--vimgrep", "--no-messages", "--pcre2", "--", pattern, str(target)],
                logs_dir,
                label,
            ),
        )
        output_path = Path(result.stdout_path)
        findings = []
        if not output_path.exists():
            return findings, result

        confidence = spec.get("confidence", "C1")
        evidence_type = spec.get("evidence_type", "string")
        tags = set(spec.get("tags") or set())
        spec_source = spec.get("source", category)

        for line in output_path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split(":", 3)
            if len(parts) != 4:
                continue
            file_path, line_str, column_str, match = parts
            try:
                line_num = int(line_str)
                col_num = int(column_str)
            except ValueError:
                line_num = None
                col_num = None
            normalized_category = category
            if category == "secret_sensitive_kv":
                lowered = match.lower()
                if "password" in lowered or "passwd" in lowered or "pwd" in lowered:
                    normalized_category = "secret_password_like"
                else:
                    normalized_category = "secret_hardcoded_token_or_apikey"
            if category == "signal_download_manager":
                normalized_category = "signal_download_manager"
            findings.append(
                self._make_finding(
                    FindingSpec(
                        category=normalized_category,
                        evidence=match.strip(),
                        file_path=file_path,
                        line=line_num,
                        column=col_num,
                        confidence=confidence,
                        evidence_type=evidence_type,
                        tags=tags,
                        sources=[f"rg:{spec_source}"],
                        source=f"rg:{spec_source}",
                    ),
                    run_dir=run_dir,
                )
            )
        return findings, result

    def _strings_findings(
        self,
        so_files: list[Path],
        logs_dir: Path,
        patterns: dict[str, re.Pattern],
        run_dir: Path,
        run_step,
    ) -> tuple[list[Finding], list[CommandResult]]:
        findings: list[Finding] = []
        results = []
        total_files = len(so_files)
        if not so_files:
            return findings, results
        scan_path = run_dir / "artifacts" / "strings_so_scan.txt"
        hits_path = run_dir / "artifacts" / "strings_so_rg_hits.txt"
        scan_path.parent.mkdir(parents=True, exist_ok=True)
        with scan_path.open("w", encoding="utf-8") as scan_handle, hits_path.open(
            "w", encoding="utf-8"
        ) as hits_handle:
            for index, so_file in enumerate(so_files, start=1):
                label = f"strings_{index}"
                progress_label = f"Strings ({index}/{total_files}): {so_file.name}"
                result = run_step(
                    progress_label,
                    lambda so_file=so_file, label=label: self._run_tool(
                        "strings",
                        ["strings", "-a", "-n", "8", str(so_file)],
                        logs_dir,
                        label,
                    ),
                )
                results.append(result)
                output_path = Path(result.stdout_path)
                if not output_path.exists():
                    continue
                try:
                    content = output_path.read_text(encoding="utf-8", errors="replace")
                except (OSError, UnicodeError):
                    content = ""
                if content:
                    scan_handle.write(f"### {so_file}\n")
                    scan_handle.write(content)
                    if not content.endswith("\n"):
                        scan_handle.write("\n")
                findings.extend(
                    self._scan_strings_output(
                        output_path,
                        patterns,
                        so_file,
                        run_dir,
                        hits_handle=hits_handle,
                    )
                )
        return findings, results

    def _scan_strings_output(
        self,
        output_path: Path,
        patterns: dict[str, re.Pattern],
        so_file: Path,
        run_dir: Path,
        hits_handle: TextIO | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for line_num, line in enumerate(
            output_path.read_text(encoding="utf-8", errors="replace").splitlines(),
            start=1,
        ):
            for category, regex in patterns.items():
                match = regex.search(line)
                if not match:
                    continue
                if hits_handle is not None:
                    hits_handle.write(f"{so_file}:{line_num}:{match.group(0)}\n")
                meta = self.STRINGS_CATEGORY_META.get(category, {"tags": set(), "category": category})
                normalized_category = meta["category"]
                findings.append(
                    self._make_finding(
                        FindingSpec(
                            category=normalized_category,
                            evidence=match.group(0),
                            file_path=str(so_file),
                            line=line_num,
                            column=None,
                            confidence="C1",
                            evidence_type="string",
                            tags=meta["tags"],
                            sources=[f"strings:{category}"],
                            source=f"strings:{category}",
                        ),
                        run_dir=run_dir,
                    )
                )
        return findings

    def _list_cert_entries(self, apk_path: Path) -> list[str]:
        try:
            with zipfile.ZipFile(apk_path, "r") as handle:
                return [
                    name
                    for name in handle.namelist()
                    if name.upper().startswith("META-INF/")
                    and name.upper().endswith((".RSA", ".DSA", ".EC"))
                ]
        except (OSError, zipfile.BadZipFile):
            return []

    def _parse_cert_listing(self, listing_path: Path) -> list[str]:
        if not listing_path.exists():
            return []
        pattern = re.compile(self.CERT_LIST_PATTERN, re.IGNORECASE)
        names: list[str] = []
        seen = set()
        for line in listing_path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = pattern.search(line)
            if not match:
                continue
            name = match.group(0)
            if name in seen:
                continue
            seen.add(name)
            names.append(name)
        return names

    def _count_zip_entries(self, apk_path: Path, suffix: str) -> int:
        try:
            with zipfile.ZipFile(apk_path, "r") as handle:
                return sum(1 for name in handle.namelist() if name.lower().endswith(suffix.lower()))
        except (OSError, zipfile.BadZipFile):
            return 0

    def _emit_progress(
        self,
        message: str,
        completed: int,
        total: int,
        elapsed_sec: float,
        eta_sec: int | None,
    ) -> None:
        if not self.on_progress:
            return
        payload = {
            "message": message,
            "completed": completed,
            "total": total,
            "elapsed_sec": elapsed_sec,
            "eta_sec": eta_sec,
        }
        if self._run_dir:
            payload["run_dir"] = str(self._run_dir)
        self.on_progress(payload)

    def _relative_path(self, file_path: str, run_dir: Path) -> str:
        path = Path(file_path)
        if not path.is_absolute():
            path = run_dir / path
        try:
            return str(path.resolve().relative_to(run_dir.resolve()))
        except (OSError, ValueError):
            return file_path

    def _make_finding(self, spec: FindingSpec, run_dir: Path | None = None) -> Finding:
        resolved_run_dir = run_dir or self._run_dir
        if resolved_run_dir is None:
            raise ValueError("run_dir is required to build a finding.")
        rel_path = self._relative_path(spec.file_path, resolved_run_dir) if spec.file_path else ""
        location = rel_path
        if spec.line is not None:
            location += f":{spec.line}"
            if spec.column is not None:
                location += f":{spec.column}"
        return Finding(
            category=spec.category,
            evidence=spec.evidence,
            match=spec.evidence,
            file_path=rel_path,
            line=spec.line,
            column=spec.column,
            confidence=spec.confidence,
            evidence_type=spec.evidence_type,
            tags=set(spec.tags or set()),
            sources=list(spec.sources or []),
            source=spec.source,
            location=location,
        )

    def _add_manifest_finding(
        self,
        findings: list[Finding],
        manifest_path: Path,
        run_dir: Path,
        category: str,
        evidence: str,
        tags: set[str] | None = None,
        sources: list[str] | None = None,
    ) -> None:
        findings.append(
            self._make_finding(
                FindingSpec(
                    category=category,
                    evidence=evidence,
                    file_path=str(manifest_path),
                    line=None,
                    column=None,
                    confidence="C3",
                    evidence_type="manifest",
                    tags=tags or set(),
                    sources=sources or [],
                    source=None,
                ),
                run_dir=run_dir,
            )
        )

    def _manifest_permissions(self, root, ns: str) -> set[str]:
        permissions = set()
        for perm in root.findall("uses-permission") + root.findall("uses-permission-sdk-23"):
            name = perm.get(f"{ns}name") or perm.get("name")
            if name:
                permissions.add(name)
        return permissions

    def _manifest_target_sdk(self, root, ns: str) -> int | None:
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is None:
            return None
        target_sdk = uses_sdk.get(f"{ns}targetSdkVersion") or uses_sdk.get("targetSdkVersion")
        if target_sdk and target_sdk.isdigit():
            return int(target_sdk)
        return None

    def _manifest_app_flags(self, application, ns: str) -> tuple[bool, bool, bool, str | None, set[str]]:
        debuggable = False
        allow_backup = False
        uses_cleartext = False
        full_backup_content = None
        foreground_types: set[str] = set()
        if application is None:
            return debuggable, allow_backup, uses_cleartext, full_backup_content, foreground_types
        debuggable = (application.get(f"{ns}debuggable") or "false").lower() == "true"
        allow_backup = (application.get(f"{ns}allowBackup") or "false").lower() == "true"
        uses_cleartext = (application.get(f"{ns}usesCleartextTraffic") or "false").lower() == "true"
        full_backup_content = application.get(f"{ns}fullBackupContent")
        for service in application.findall("service"):
            fst = service.get(f"{ns}foregroundServiceType")
            if fst:
                for item in fst.split("|"):
                    foreground_types.add(item.strip())
        return debuggable, allow_backup, uses_cleartext, full_backup_content, foreground_types

    def _add_manifest_permission_findings(
        self,
        findings: list[Finding],
        manifest_path: Path,
        run_dir: Path,
        permissions: set[str],
        foreground_types: set[str],
    ) -> None:
        def has_permission(name: str) -> bool:
            return name in permissions

        location_permissions = {
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
        }
        has_location = any(has_permission(perm) for perm in location_permissions)
        has_background_location = has_permission("android.permission.ACCESS_BACKGROUND_LOCATION")
        if "location" in foreground_types:
            has_background_location = True

        if has_location:
            if has_background_location:
                self._add_manifest_finding(
                    findings,
                    manifest_path,
                    run_dir,
                    "ndv_geo_tracking_background",
                    "location permissions (background)",
                    tags={"background"},
                    sources=["manifest:permission:location"],
                )
            else:
                self._add_manifest_finding(
                    findings,
                    manifest_path,
                    run_dir,
                    "ndv_geo_tracking_foreground",
                    "location permissions",
                    sources=["manifest:permission:location"],
                )

        if has_permission("android.permission.RECORD_AUDIO"):
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "ndv_mic_eavesdropping",
                "android.permission.RECORD_AUDIO",
                sources=["manifest:permission:RECORD_AUDIO"],
            )
        if has_permission("android.permission.CAMERA"):
            tags = {"background"} if "camera" in foreground_types else set()
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "ndv_camera_surveillance",
                "android.permission.CAMERA",
                tags=tags,
                sources=["manifest:permission:CAMERA"],
            )
        if has_permission("android.permission.BIND_ACCESSIBILITY_SERVICE"):
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "ndv_accessibility_surveillance",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                tags={"background"},
                sources=["manifest:permission:BIND_ACCESSIBILITY_SERVICE"],
            )
        if has_permission("android.permission.SYSTEM_ALERT_WINDOW"):
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "ndv_overlay_abuse",
                "android.permission.SYSTEM_ALERT_WINDOW",
                sources=["manifest:permission:SYSTEM_ALERT_WINDOW"],
            )
        if has_permission("android.permission.READ_SMS") or has_permission("android.permission.RECEIVE_SMS"):
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "ndv_sms_intercept",
                "android.permission.READ_SMS/RECEIVE_SMS",
                sources=["manifest:permission:SMS"],
            )
        if has_permission("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"):
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "ndv_notification_listener",
                "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
                sources=["manifest:permission:BIND_NOTIFICATION_LISTENER_SERVICE"],
            )

        if "mediaProjection" in foreground_types:
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "ndv_screen_capture_mediaprojection",
                "foregroundServiceType=mediaProjection",
                tags={"background"},
                sources=["manifest:foregroundServiceType:mediaProjection"],
            )

    def _component_exported(self, component, tag: str, ns: str) -> bool:
        exported = component.get(f"{ns}exported")
        if exported is not None:
            return exported.lower() == "true"
        has_intent = component.find("intent-filter") is not None
        return has_intent and tag in ("activity", "activity-alias", "service", "receiver")

    def _component_has_permission(self, component, ns: str) -> bool:
        attrs = [
            component.get(f"{ns}permission"),
            component.get(f"{ns}readPermission"),
            component.get(f"{ns}writePermission"),
        ]
        return any(attrs)

    def _component_has_deeplink(self, component, ns: str) -> bool:
        for intent_filter in component.findall("intent-filter"):
            has_view = any(
                (action.get(f"{ns}name") or "").endswith(".VIEW")
                or (action.get(f"{ns}name") == "android.intent.action.VIEW")
                for action in intent_filter.findall("action")
            )
            if not has_view:
                continue
            has_browsable = any(
                (cat.get(f"{ns}name") or "").endswith(".BROWSABLE")
                or (cat.get(f"{ns}name") == "android.intent.category.BROWSABLE")
                for cat in intent_filter.findall("category")
            )
            has_data = intent_filter.find("data") is not None
            if has_browsable or has_data:
                return True
        return False

    def _component_has_boot_completed(self, component, ns: str) -> bool:
        for intent_filter in component.findall("intent-filter"):
            for action in intent_filter.findall("action"):
                action_name = action.get(f"{ns}name") or ""
                if action_name == "android.intent.action.BOOT_COMPLETED":
                    return True
        return False

    def _add_manifest_component_findings(
        self,
        findings: list[Finding],
        manifest_path: Path,
        run_dir: Path,
        application,
        ns: str,
    ) -> None:
        if application is None:
            return
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for component in application.findall(tag):
                exported = self._component_exported(component, tag, ns)
                name = component.get(f"{ns}name") or component.get("name") or "unknown"
                if exported and not self._component_has_permission(component, ns):
                    self._add_manifest_finding(
                        findings,
                        manifest_path,
                        run_dir,
                        "vul_exported_component_no_permission",
                        f"{tag}:{name} exported without permission",
                        tags={"exported"},
                        sources=[f"manifest:exported:{tag}"],
                    )
                if tag == "provider":
                    grant_uri = (component.get(f"{ns}grantUriPermissions") or "false").lower() == "true"
                    if exported or grant_uri:
                        self._add_manifest_finding(
                            findings,
                            manifest_path,
                            run_dir,
                            "vul_exported_provider_risky",
                            f"provider:{name} exported/grantUriPermissions",
                            tags={"exported"},
                            sources=["manifest:provider"],
                        )
                    if "FileProvider" in name and (exported or grant_uri):
                        self._add_manifest_finding(
                            findings,
                            manifest_path,
                            run_dir,
                            "vul_fileprovider_misconfig",
                            f"FileProvider:{name} exported/grantUriPermissions",
                            tags={"exported"},
                            sources=["manifest:fileprovider"],
                        )
                if tag in ("activity", "activity-alias") and exported:
                    if self._component_has_deeplink(component, ns):
                        self._add_manifest_finding(
                            findings,
                            manifest_path,
                            run_dir,
                            "vul_deeplink_intent_injection",
                            f"deeplink:{name} exported",
                            tags={"exported"},
                            sources=["manifest:deeplink"],
                        )
                if tag == "receiver" and self._component_has_boot_completed(component, ns):
                    self._add_manifest_finding(
                        findings,
                        manifest_path,
                        run_dir,
                        "persist_boot_completed",
                        f"receiver:{name} BOOT_COMPLETED",
                        tags={"persistence", "background"},
                        sources=["manifest:boot_completed"],
                    )
                if tag == "service":
                    perm = component.get(f"{ns}permission") or ""
                    if perm == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE":
                        self._add_manifest_finding(
                            findings,
                            manifest_path,
                            run_dir,
                            "ndv_notification_listener",
                            f"service:{name} notification listener",
                            sources=["manifest:notification_listener_service"],
                        )

    def _manifest_findings(
        self,
        apktool_dir: Path,
        run_dir: Path,
        logs_dir: Path,
    ) -> tuple[list[Finding], dict]:
        findings: list[Finding] = []
        manifest_path = apktool_dir / "AndroidManifest.xml"
        meta = {"target_sdk": None, "permissions": set()}
        if not manifest_path.exists():
            meta.update(self._parse_aapt2_info(logs_dir))
            return findings, meta

        ns = "{http://schemas.android.com/apk/res/android}"
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
        except (ET.ParseError, OSError):
            meta.update(self._parse_aapt2_info(logs_dir))
            return findings, meta
        permissions = self._manifest_permissions(root, ns)
        meta["permissions"] = permissions
        target_sdk = self._manifest_target_sdk(root, ns)
        if target_sdk is not None:
            meta["target_sdk"] = target_sdk

        application = root.find("application")
        debuggable, allow_backup, uses_cleartext, full_backup_content, foreground_types = (
            self._manifest_app_flags(application, ns)
        )

        if debuggable:
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "vul_debuggable_true",
                "android:debuggable=true",
                sources=["manifest:debuggable"],
            )
        if allow_backup:
            evidence = "android:allowBackup=true"
            if not full_backup_content:
                evidence += " (fullBackupContent missing)"
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "vul_backup_enabled",
                evidence,
                sources=["manifest:allowBackup"],
            )
        if uses_cleartext:
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "sec_cleartext_traffic_allowed",
                "android:usesCleartextTraffic=true",
                tags={"mitm_enabler", "network"},
                sources=["manifest:usesCleartextTraffic"],
            )

        self._add_manifest_permission_findings(
            findings,
            manifest_path,
            run_dir,
            permissions,
            foreground_types,
        )
        self._add_manifest_component_findings(
            findings,
            manifest_path,
            run_dir,
            application,
            ns,
        )

        meta.update(self._parse_aapt2_info(logs_dir))
        return findings, meta

    def _parse_aapt2_info(self, logs_dir: Path) -> dict:
        info: dict[str, int] = {}
        stdout_path = logs_dir / "aapt2.stdout.txt"
        if not stdout_path.exists():
            return info
        text = stdout_path.read_text(encoding="utf-8", errors="replace")
        match = re.search(r"targetSdkVersion:'(\d+)'", text)
        if match:
            info["target_sdk"] = int(match.group(1))
        return info

    def _apksigner_findings(
        self,
        logs_dir: Path,
        run_dir: Path,
        target_sdk: int | None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        stdout_path = logs_dir / "apksigner.stdout.txt"
        stderr_path = logs_dir / "apksigner.stderr.txt"
        if not stdout_path.exists() and not stderr_path.exists():
            return findings
        text = ""
        if stdout_path.exists():
            text += stdout_path.read_text(encoding="utf-8", errors="replace")
        if stderr_path.exists():
            text += "\n" + stderr_path.read_text(encoding="utf-8", errors="replace")

        rel_path = self._relative_path(str(stdout_path), run_dir)

        if re.search(r"DOES NOT VERIFY|ERROR", text, re.IGNORECASE):
            findings.append(
                self._make_finding(
                    FindingSpec(
                        category="supplychain_signature_invalid",
                        evidence="apksigner verification failed",
                        file_path=rel_path,
                        line=None,
                        column=None,
                        confidence="C3",
                        evidence_type="signing",
                        tags=set(),
                        sources=["apksigner:verify"],
                        source="apksigner:verify",
                    ),
                    run_dir=run_dir,
                )
            )

        if "Android Debug" in text:
            findings.append(
                self._make_finding(
                    FindingSpec(
                        category="supplychain_debug_certificate",
                        evidence="Android Debug certificate",
                        file_path=rel_path,
                        line=None,
                        column=None,
                        confidence="C3",
                        evidence_type="signing",
                        tags=set(),
                        sources=["apksigner:debug_cert"],
                        source="apksigner:debug_cert",
                    ),
                    run_dir=run_dir,
                )
            )

        v1 = self._parse_apksigner_bool(text, "v1")
        v2 = self._parse_apksigner_bool(text, "v2")
        v3 = self._parse_apksigner_bool(text, "v3")
        if target_sdk is not None and target_sdk >= 24 and v1 and not v2 and not v3:
            findings.append(
                self._make_finding(
                    FindingSpec(
                        category="supplychain_signature_scheme_v1_only",
                        evidence="v1-only signature scheme",
                        file_path=rel_path,
                        line=None,
                        column=None,
                        confidence="C3",
                        evidence_type="signing",
                        tags=set(),
                        sources=["apksigner:scheme"],
                        source="apksigner:scheme",
                    ),
                    run_dir=run_dir,
                )
            )

        return findings

    def _parse_apksigner_bool(self, text: str, scheme: str) -> bool:
        pattern = re.compile(rf"Verified using v{scheme} scheme.*?:\s*(true|false)", re.IGNORECASE)
        match = pattern.search(text)
        if not match:
            return False
        return match.group(1).lower() == "true"

    def _keytool_findings(self, logs_dir: Path, run_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in sorted(logs_dir.glob("keytool_*.stdout.txt")):
            text = path.read_text(encoding="utf-8", errors="replace")
            rel_path = self._relative_path(str(path), run_dir)
            if re.search(r"CN=Android Debug", text):
                findings.append(
                    self._make_finding(
                        FindingSpec(
                            category="supplychain_debug_certificate",
                            evidence="Android Debug certificate",
                            file_path=rel_path,
                            line=None,
                            column=None,
                            confidence="C3",
                            evidence_type="signing",
                            tags=set(),
                            sources=[f"keytool:{path.name}"],
                            source=f"keytool:{path.name}",
                        ),
                        run_dir=run_dir,
                    )
                )
            expired = self._keytool_cert_expired(text)
            if expired:
                findings.append(
                    self._make_finding(
                        FindingSpec(
                            category="supplychain_cert_expired",
                            evidence="certificate expired",
                            file_path=rel_path,
                            line=None,
                            column=None,
                            confidence="C3",
                            evidence_type="signing",
                            tags=set(),
                            sources=[f"keytool:{path.name}"],
                            source=f"keytool:{path.name}",
                        ),
                        run_dir=run_dir,
                    )
                )
        return findings

    def _keytool_cert_expired(self, text: str) -> bool:
        match = re.search(r"Valid from:\s*(.+?)\s*until:\s*(.+)", text)
        if not match:
            return False
        until_raw = match.group(2).strip()
        for fmt in ("%a %b %d %H:%M:%S %Z %Y", "%a %b %d %H:%M:%S %Y"):
            try:
                until = datetime.strptime(until_raw, fmt)
                return until < datetime.now()
            except ValueError:
                continue
        return False

    def _yara_findings(self, logs_dir: Path, run_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        stdout_path = logs_dir / "yara.stdout.txt"
        if not stdout_path.exists():
            return findings
        for line in stdout_path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                continue
            rule_name, file_path = parts[0].strip(), parts[1].strip()
            mapping = self.YARA_RULE_CATEGORY.get(rule_name)
            if not mapping:
                continue
            category, tags = mapping
            findings.append(
                self._make_finding(
                    FindingSpec(
                        category=category,
                        evidence=rule_name,
                        file_path=file_path,
                        line=None,
                        column=None,
                        confidence="C2",
                        evidence_type="code",
                        tags=set(tags),
                        sources=[f"yara:{rule_name}"],
                        source=f"yara:{rule_name}",
                    ),
                    run_dir=run_dir,
                )
            )
        return findings

    def _obfuscation_findings(self, jadx_dir: Path, run_dir: Path) -> list[Finding]:
        sources_dir = jadx_dir / "sources"
        if not sources_dir.exists():
            return []
        java_files = list(sources_dir.rglob("*.java")) + list(sources_dir.rglob("*.kt"))
        if len(java_files) < 50:
            return []
        short_names = [path for path in java_files if len(path.stem) <= 2]
        ratio = len(short_names) / max(1, len(java_files))
        if ratio < 0.4:
            return []
        evidence = f"short class names ratio {ratio:.2f} ({len(short_names)}/{len(java_files)})"
        return [
            self._make_finding(
                FindingSpec(
                    category="anomaly_obfuscation_heavy",
                    evidence=evidence,
                    file_path=str(sources_dir),
                    line=None,
                    column=None,
                    confidence="C2",
                    evidence_type="code",
                    tags=set(),
                    sources=["jadx:obfuscation"],
                    source="jadx:obfuscation",
                ),
                run_dir=run_dir,
            )
        ]

    def _post_process_findings(self, findings: list[Finding], run_dir: Path) -> list[Finding]:
        findings = self._aggregate_reflection_findings(findings, run_dir)
        findings = self._apply_download_execute(findings, run_dir)
        findings = self._apply_persistence_boost(findings)
        return self._dedupe_findings(findings)

    def _aggregate_reflection_findings(self, findings: list[Finding], run_dir: Path) -> list[Finding]:
        reflection = [finding for finding in findings if finding.category == "ndv_reflection_heavy"]
        if not reflection:
            return findings
        if len(reflection) < 25:
            return [f for f in findings if f.category != "ndv_reflection_heavy"]
        sample = reflection[0]
        aggregated = self._make_finding(
            FindingSpec(
                category="ndv_reflection_heavy",
                evidence=f"reflection calls: {len(reflection)}",
                file_path=sample.file_path,
                line=None,
                column=None,
                confidence=sample.confidence or "C2",
                evidence_type=sample.evidence_type or "code",
                tags=set(sample.tags),
                sources=sample.sources or ["rg:reflection"],
                source=sample.source,
            ),
            run_dir=run_dir,
        )
        remaining = [f for f in findings if f.category != "ndv_reflection_heavy"]
        remaining.append(aggregated)
        return remaining

    def _apply_download_execute(self, findings: list[Finding], run_dir: Path) -> list[Finding]:
        downloads = [f for f in findings if f.category == "signal_download_manager"]
        if not downloads:
            return findings
        code_exec = [
            f
            for f in findings
            if f.category
            in (
                "ndv_dynamic_code_loading",
                "ndv_native_code_loader_suspicious",
                "ndv_remote_command",
            )
        ]
        if not code_exec:
            return [f for f in findings if f.category != "signal_download_manager"]
        combined = []
        for hit in downloads:
            combined.append(
                self._make_finding(
                    FindingSpec(
                        category="ndv_download_execute",
                        evidence="DownloadManager + dynamic code loading",
                        file_path=hit.file_path or "",
                        line=hit.line,
                        column=hit.column,
                        confidence="C2",
                        evidence_type="code",
                        tags={"network", "dynamic_code"},
                        sources=hit.sources or ["rg:download_manager"],
                        source=hit.source,
                    ),
                    run_dir=run_dir,
                )
            )
        filtered = [f for f in findings if f.category != "signal_download_manager"]
        filtered.extend(combined)
        return filtered

    def _apply_persistence_boost(self, findings: list[Finding]) -> list[Finding]:
        persistence_categories = {
            "persist_boot_completed",
            "persist_workmanager_periodic",
            "persist_jobscheduler_periodic",
            "persist_alarmmanager_repeating",
        }
        has_persistence = any(f.category in persistence_categories for f in findings)
        if not has_persistence:
            return findings
        for finding in findings:
            if finding.category in persistence_categories:
                continue
            if any(
                source.startswith("rg:endpoint_")
                for source in (finding.sources or [])
            ):
                continue
            finding.tags.add("persistence")
        return findings

    def _dedupe_findings(self, findings: list[Finding]) -> list[Finding]:
        seen: set[tuple] = set()
        deduped: list[Finding] = []
        for finding in findings:
            key = (
                finding.category,
                finding.evidence,
                finding.file_path,
                finding.line,
                finding.column,
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped

    def _write_report(self, report_path: Path, run: Run, findings: list[Finding]) -> None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        category_counts: dict[str, int] = {}
        for finding in findings:
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
        lines = [
            "# Stage 1 Static Analysis Report",
            "",
            f"- Run ID: {run.run_id}",
            f"- Project ID: {run.project_id}",
            f"- Status: {run.status}",
            f"- Started At: {run.started_at}",
            f"- Finished At: {run.finished_at or 'N/A'}",
            f"- APK Path: {run.apk_path}",
            "",
            "## Findings Summary",
        ]
        if category_counts:
            for category, count in sorted(category_counts.items()):
                lines.append(f"- {category}: {count}")
        else:
            lines.append("- No findings")

        lines.append("")
        lines.append("## Findings")
        if findings:
            for finding in findings:
                location = finding.file_path
                if finding.line is not None:
                    location += f":{finding.line}"
                    if finding.column is not None:
                        location += f":{finding.column}"
                source = ", ".join(finding.sources) if finding.sources else (finding.source or "unknown")
                severity = finding.severity or "info"
                evidence = finding.evidence or finding.match or ""
                lines.append(
                    f"- [{severity.upper()}] [{finding.category}] {evidence} ({location}) [{source}]"
                )
        else:
            lines.append("- None")

        if run.errors:
            lines.append("")
            lines.append("## Errors")
            for error in run.errors:
                lines.append(f"- {error}")

        report_path.write_text("\n".join(lines), encoding="utf-8")

    def _write_report_json(self, report_path: Path, run: Run, findings: list[Finding]) -> None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "run": run.model_dump(mode="json"),
            "findings": [finding.model_dump(mode="json") for finding in findings],
        }
        report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
