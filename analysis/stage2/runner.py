from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Callable

from analysis.models.stage2 import Stage2Config, Stage2Finding
from analysis.reporting import ReportManager
from analysis.runtime.clock import now_utc_iso
from analysis.runtime.context import RunContext
from analysis.runtime.exec import run_command_capture
from analysis.runtime.fs import (
    ensure_run_dir,
    ensure_run_json,
    write_run_finished,
    write_tool_bundle,
)
from analysis.stage2._sdk import find_sdk_bin
from analysis.stage2.diff import SnapshotDiff
from analysis.stage2.emulator import EmulatorManager
from analysis.stage2.exerciser import UiExerciser
from analysis.stage2.installer import ApkInstaller
from analysis.stage2.logcat import LogcatCapture
from analysis.stage2.snapshot import SystemSnapshot
from analysis.stage2.traffic import TrafficCapture
from analysis.stage2.zeek import ZeekAnalyzer
from analysis.stage3_common import append_run_error, build_stage3_logger
from analysis.stages import STAGE_DYNAMIC
from analysis.storage import Storage
from models import Run


class _PidMonitor:
    """Background thread that polls the app PID every 5s during capture.

    Records first/last seen timestamps and detects when the process exits
    before the capture window ends (crash, kill, anti-analysis exit).
    """

    def __init__(self, pkg_name: str, adb_bin: str, adb_timeout: int) -> None:
        self.pkg_name = pkg_name
        self.adb_bin = adb_bin
        self.adb_timeout = adb_timeout
        self.pid_first_seen: str = ""
        self.pid_last_seen: str = ""
        self.app_died_at: str = ""  # UTC ISO when PID first disappeared
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self, initial_pid: str) -> None:
        self.pid_first_seen = initial_pid
        self.pid_last_seen = initial_pid
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._thread.join(timeout=10)

    def _run(self) -> None:
        while not self._stop_event.wait(5):
            _, out, _ = run_command_capture(
                [self.adb_bin, "shell", "pidof", self.pkg_name],
                timeout=self.adb_timeout,
            )
            pid = out.strip()
            if pid:
                self.pid_last_seen = pid
                self.app_died_at = ""  # reset if app restarted
            elif not self.app_died_at:
                self.app_died_at = now_utc_iso()


class Stage2DynamicRunner:
    def __init__(
        self,
        storage: Storage,
        config: Stage2Config | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> None:
        self.storage = storage
        self.config = config or Stage2Config()
        self.on_progress = on_progress

    def run(self, project_id: str, ctx: RunContext | None = None) -> Run:
        if ctx is None:
            ctx = self.storage.get_or_create_stage2_run(project_id)

        run_dir = ctx.run_dir
        apk_path = Path(ctx.apk_path)
        run = Run(
            run_id=ctx.run_id,
            project_id=project_id,
            stage=STAGE_DYNAMIC,
            started_at=ctx.started_at,
            apk_path=str(apk_path),
        )
        ensure_run_dir(ctx)
        ensure_run_json(ctx)

        log = build_stage3_logger(run_dir / "logs" / "stage2.log", self.on_progress)
        log("Stage 2 Dynamic Analysis started.")

        tools_dir = run_dir / "tools"
        snap_dir = tools_dir / "adb_snapshot"
        diffs_dir = run_dir / "diffs"
        artifacts_dir = run_dir / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        stage2_data: dict = {}

        adb = find_sdk_bin("adb")
        emulator = EmulatorManager(
            avd_name=self.config.avd_name,
            adb_timeout_sec=self.config.adb_timeout_sec,
            on_log=log,
        )
        snap = SystemSnapshot(adb_timeout_sec=self.config.adb_timeout_sec, on_log=log)
        installer = ApkInstaller(adb_timeout_sec=self.config.adb_timeout_sec, on_log=log)
        differ = SnapshotDiff(on_log=log)
        logcat = LogcatCapture(adb_timeout_sec=self.config.adb_timeout_sec, on_log=log)
        traffic = TrafficCapture(adb_timeout_sec=self.config.adb_timeout_sec, on_log=log)
        zeek = ZeekAnalyzer(on_log=log)

        tools_index: list[dict] = []
        traffic_started = False
        pkg_name = ""
        app_uid = ""
        app_pid = ""
        pid_monitor: _PidMonitor | None = None
        exerciser_sent = 0
        exerciser_total = 0
        run_start_ts = time.monotonic()

        try:
            # ----------------------------------------------------------------
            # Step 1: Start emulator
            # ----------------------------------------------------------------
            boot_start = time.monotonic()
            log("Step 1: Starting emulator...")
            emulator.start(headless=True)
            booted = emulator.wait_boot(timeout_sec=self.config.emulator_boot_timeout_sec)
            if not booted:
                raise RuntimeError(
                    f"Emulator failed to boot within {self.config.emulator_boot_timeout_sec}s. "
                    "Ensure KVM is available and AVD exists."
                )
            boot_time = int(time.monotonic() - boot_start)
            emulator.root()

            _, adb_ver_out, _ = run_command_capture([adb, "version"], timeout=10)
            adb_version = adb_ver_out.strip().splitlines()[0] if adb_ver_out.strip() else ""

            stage2_data["environment"] = {
                "avd_name": self.config.avd_name,
                "api_level": self.config.api_level,
                "adb_version": adb_version,
                "boot_time_sec": boot_time,
            }
            log(f"Emulator ready in {boot_time}s.")

            # ----------------------------------------------------------------
            # Step 2: Baseline snapshot
            # ----------------------------------------------------------------
            log("Step 2: Capturing baseline snapshot...")
            snap_before = snap.capture("before", snap_dir)

            # ----------------------------------------------------------------
            # Step 3: APK install → resolve UID
            # ----------------------------------------------------------------
            log("Step 3: Installing APK...")
            t_install_start = now_utc_iso()
            install_code, install_stdout, install_stderr = installer.install(apk_path)
            t_install_end = now_utc_iso()
            idx = write_tool_bundle(
                ctx, "adb_install",
                cmd=["adb", "install", "-r", str(apk_path)],
                started_at=t_install_start,
                finished_at=t_install_end,
                exit_code=install_code,
                stdout=install_stdout,
                stderr=install_stderr,
                artifacts={},
            )
            tools_index.append(idx)
            if install_code != 0:
                raise RuntimeError(f"APK installation failed (exit={install_code}).")

            pkg_name = self._get_package_name(apk_path, run_dir, log)
            log(f"Package name: {pkg_name or '(unknown)'}")

            if pkg_name:
                app_uid = self._resolve_uid(pkg_name, adb, log)
                if app_uid:
                    log(f"App UID: {app_uid}")

            # ----------------------------------------------------------------
            # Step 4: Post-install snapshot
            # ----------------------------------------------------------------
            log("Step 4: Post-install snapshot...")
            snap_after_install = snap.capture("after_install", snap_dir)

            # ----------------------------------------------------------------
            # Step 5: Install diff
            # ----------------------------------------------------------------
            log("Step 5: Computing install diff...")
            install_diff = differ.compute(snap_before, snap_after_install, diffs_dir)
            stage2_data["install_diff"] = {
                "new_packages": install_diff.new_packages,
                "new_paths": install_diff.new_paths[:50],
                "fs_diff_path": install_diff.fs_diff_path,
                "packages_diff_path": install_diff.packages_diff_path,
            }

            # ----------------------------------------------------------------
            # Step 6: Start logcat + traffic capture
            # ----------------------------------------------------------------
            log("Step 6: Starting logcat and traffic capture...")
            logcat_path = tools_dir / "adb_logcat" / "logcat_runtime.txt"
            t_runtime_start = now_utc_iso()
            capture_start_ts = time.monotonic()  # measure only the capture window
            logcat.start(logcat_path)
            pcap_local = tools_dir / "adb_traffic" / "traffic_runtime.pcap"
            traffic_started = traffic.start()

            # ----------------------------------------------------------------
            # Step 7: Launch app → resolve PID → start PID logcat + monitor
            # ----------------------------------------------------------------
            exerciser: UiExerciser | None = None
            if pkg_name:
                log(f"Step 7: Launching app ({pkg_name})...")
                run_command_capture(
                    [adb, "shell", "monkey", "-p", pkg_name,
                     "-c", "android.intent.category.LAUNCHER", "1"],
                    timeout=self.config.adb_timeout_sec,
                )
                time.sleep(2)

                # Resolve PID and start PID-filtered logcat
                app_pid = self._resolve_pid(pkg_name, adb, log)
                if app_pid:
                    pid_logcat_path = tools_dir / "adb_logcat" / "logcat_app_pid.txt"
                    logcat.start_pid_filter(app_pid, pid_logcat_path)
                    # Start background PID monitor
                    pid_monitor = _PidMonitor(pkg_name, adb, self.config.adb_timeout_sec)
                    pid_monitor.start(app_pid)

                # Start Monkey stress test in background
                exerciser = UiExerciser(
                    package=pkg_name,
                    duration_sec=self.config.runtime_duration_sec,
                    on_log=log,
                )
                exerciser.start()
                exerciser_total = exerciser.events
            else:
                log("Step 7: Package name unknown, skipping Monkey launch.")

            log(f"Capturing for {self.config.runtime_duration_sec}s...")
            time.sleep(self.config.runtime_duration_sec)

            # ----------------------------------------------------------------
            # Step 8: Stop exerciser + monitors + logcat + traffic
            # ----------------------------------------------------------------
            log("Step 8: Stopping UI exerciser, logcat, and traffic capture...")
            if exerciser is not None:
                exerciser.stop()
                exerciser_sent = exerciser._sent  # noqa: SLF001

            if pid_monitor is not None:
                pid_monitor.stop()

            logcat_out, pid_logcat_out = logcat.stop()
            t_runtime_end = now_utc_iso()

            idx = write_tool_bundle(
                ctx, "adb_logcat",
                cmd=["adb", "logcat"],
                started_at=t_runtime_start,
                finished_at=t_runtime_end,
                exit_code=0,
                stdout="",
                stderr="",
                artifacts={
                    "logcat": logcat_out,
                    **({"logcat_pid": pid_logcat_out} if pid_logcat_out else {}),
                },
            )
            tools_index.append(idx)

            if traffic_started:
                traffic.stop_and_pull(pcap_local)

            idx = write_tool_bundle(
                ctx, "adb_traffic",
                cmd=["adb", "shell", "tcpdump", "-i", "any", "-p", "-s", "0",
                     "-w", "/sdcard/traffic.pcap"],
                started_at=t_runtime_start,
                finished_at=t_runtime_end,
                exit_code=0 if traffic_started else 1,
                stdout="",
                stderr="" if traffic_started else "tcpdump not available on device",
                artifacts={"pcap": str(pcap_local)},
            )
            tools_index.append(idx)

            # ----------------------------------------------------------------
            # Step 8.5: Force-stop app before snapshot (flush DBs, release locks)
            # ----------------------------------------------------------------
            if pkg_name:
                log(f"Force-stopping {pkg_name} before snapshot...")
                run_command_capture(
                    [adb, "shell", "am", "force-stop", pkg_name],
                    timeout=self.config.adb_timeout_sec,
                )
                time.sleep(1)  # brief wait for OS to flush

            # ----------------------------------------------------------------
            # Step 9: Post-runtime snapshot + diff
            # ----------------------------------------------------------------
            log("Step 9: Post-runtime snapshot and diff...")
            snap_after_runtime = snap.capture("after_runtime", snap_dir)
            runtime_diff = differ.compute(snap_after_install, snap_after_runtime, diffs_dir)

            # ----------------------------------------------------------------
            # Step 9.5: Target-package file listing + appops snapshot
            # ----------------------------------------------------------------
            pkg_files: list[str] = []
            appops_path = ""
            if pkg_name:
                pkg_files = self._capture_pkg_files(pkg_name, adb, tools_dir, log)
                appops_path = self._capture_appops(pkg_name, adb, tools_dir, log)

            stage2_data["runtime_diff"] = {
                "logcat_path": logcat_out,
                "pid_logcat_path": pid_logcat_out,
                "new_paths": runtime_diff.new_paths[:50],
                "fs_diff_path": runtime_diff.fs_diff_path,
                "target_pkg_files": pkg_files[:100],
                "target_pkg_files_count": len(pkg_files),
                "appops_path": appops_path,
            }

            # ----------------------------------------------------------------
            # Step 10: Zeek / tshark analysis (with TSV exports + alerts)
            # ----------------------------------------------------------------
            log("Step 10: Running Zeek analysis...")
            zeek_dir = tools_dir / "zeek"
            actual_duration = time.monotonic() - capture_start_ts
            net_capture = zeek.analyze(pcap_local, zeek_dir,
                                       capture_duration_sec=actual_duration)
            stage2_data["network"] = {
                "pcap_path": str(pcap_local),
                "unique_ips": net_capture.unique_ips,
                "unique_domains": net_capture.unique_domains,
                "top_hosts": net_capture.top_hosts,
                "zeek_available": net_capture.zeek_available,
                "zeek_logs": net_capture.zeek_logs,
                "tshark_tsv_files": net_capture.tshark_tsv_files,
                "tshark_alerts_summary": [
                    {"rule_id": a["rule_id"], "confidence": a["confidence"], "title": a["title"]}
                    for a in net_capture.alerts
                ],
                "tshark_alerts_path": str(zeek_dir / "tshark_alerts.json")
                    if net_capture.alerts else "",
            }
            if not net_capture.zeek_available:
                append_run_error(run, "Zeek/tshark not installed; pcap saved for manual analysis.")

            # ----------------------------------------------------------------
            # Crash detection from logcat
            # ----------------------------------------------------------------
            crash_info = self._detect_crash(logcat_out, pkg_name) if pkg_name else {}

            # ----------------------------------------------------------------
            # Coverage + attribution + findings
            # ----------------------------------------------------------------
            coverage_pct = (exerciser_sent / exerciser_total) if exerciser_total > 0 else -1.0

            pid_logcat_empty = (
                bool(pid_logcat_out) and
                Path(pid_logcat_out).exists() and
                Path(pid_logcat_out).stat().st_size == 0
            )

            app_crashed = bool(
                (pid_monitor and pid_monitor.app_died_at) or crash_info.get("detected")
            )
            crash_time = (
                pid_monitor.app_died_at
                if pid_monitor and pid_monitor.app_died_at
                else ""
            )

            stage2_data["attribution"] = {
                "package_name": pkg_name,
                "uid": app_uid,
                "pid_initial": app_pid,
                "pid_first_seen": pid_monitor.pid_first_seen if pid_monitor else app_pid,
                "pid_last_seen": pid_monitor.pid_last_seen if pid_monitor else "",
                "app_died_at": crash_time,
                "pid_logcat_captured": bool(pid_logcat_out),
                "pid_logcat_empty": pid_logcat_empty,
            }

            stage2_data["coverage"] = {
                "exerciser_events_sent": exerciser_sent,
                "exerciser_events_configured": exerciser_total,
                "exerciser_coverage_pct": round(coverage_pct * 100, 1) if coverage_pct >= 0 else -1,
                "capture_duration_sec": round(actual_duration, 1),
            }

            findings = self._build_findings(
                pkg_name=pkg_name,
                app_pid=app_pid,
                pid_logcat_out=pid_logcat_out,
                pid_logcat_empty=pid_logcat_empty,
                pkg_files=pkg_files,
                coverage_pct=coverage_pct,
                app_crashed=app_crashed,
                crash_time=crash_time,
                crash_info=crash_info,
                actual_duration=actual_duration,
                net_alerts=net_capture.alerts,
                appops_path=appops_path,
            )

            stage2_data["findings"] = [
                {
                    "finding_id": f.finding_id,
                    "confidence": f.confidence,
                    "title": f.title,
                    "detail": f.detail,
                    "evidence": f.evidence,
                }
                for f in findings
                if not f.suppressed
            ]

            # Save findings artifact
            findings_path = artifacts_dir / "stage2_findings.json"
            findings_path.write_text(
                json.dumps(stage2_data["findings"], indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

            stage2_data["correlation"] = {
                "confirmed_indicators": [],
                "new_indicators": [],
            }

        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"Stage 2 failed: {exc}")
            run.status = "Error"
            run.finished_at = now_utc_iso()  # UTC — fixes duration_sec bug
            append_run_error(run, f"Stage2 error: {exc}")
        else:
            run.status = "Done"
            run.finished_at = now_utc_iso()  # UTC — fixes duration_sec bug
            log("Stage 2 completed successfully.")
        finally:
            # Step 11: Stop emulator (always)
            try:
                emulator.stop()
            except Exception as exc:  # pylint: disable=broad-exception-caught
                log(f"Emulator stop error: {exc}")

        # Generate report
        try:
            report_manager = ReportManager(self.storage)
            _, html_path = report_manager.generate_stage2(run, run_dir, stage2_data)
            run.report_path = str(html_path)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"Report generation failed: {exc}")

        write_run_finished(ctx, now_utc_iso(), tools_index)
        log("Stage 2 run finalized.")
        return run

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_uid(self, pkg_name: str, adb: str, log: Callable) -> str:
        """Resolve UID for installed package via pm list packages -U."""
        try:
            code, out, _ = run_command_capture(
                [adb, "shell", "pm", "list", "packages", "-U"],
                timeout=self.config.adb_timeout_sec,
            )
            if code == 0:
                for line in out.splitlines():
                    if pkg_name in line:
                        # format: "package:com.foo uid:10209"
                        m = re.search(r"uid:(\d+)", line)
                        if m:
                            return m.group(1)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"UID resolution failed: {exc}")
        return ""

    def _resolve_pid(self, pkg_name: str, adb: str, log: Callable) -> str:
        """Resolve PID of running package via pidof."""
        try:
            code, out, _ = run_command_capture(
                [adb, "shell", "pidof", pkg_name],
                timeout=self.config.adb_timeout_sec,
            )
            if code == 0:
                pid = out.strip().split()[0] if out.strip() else ""
                if pid:
                    log(f"App PID: {pid}")
                    return pid
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"PID resolution failed: {exc}")
        return ""

    def _capture_pkg_files(
        self, pkg_name: str, adb: str, tools_dir: Path, log: Callable
    ) -> list[str]:
        """List files in app data directory after force-stop."""
        try:
            data_dir = f"/data/data/{pkg_name}"
            code, out, _ = run_command_capture(
                [adb, "shell", "ls", "-laR", data_dir],
                timeout=self.config.adb_timeout_sec,
            )
            out_path = tools_dir / "adb_snapshot" / f"pkg_files_{pkg_name}.txt"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if code == 0 and out.strip():
                out_path.write_text(out, encoding="utf-8", errors="replace")
                # Parse file lines (ls -la output): extract paths
                paths = [
                    ln.strip().split()[-1]
                    for ln in out.splitlines()
                    if ln.strip() and not ln.startswith("total") and not ln.startswith("/")
                    and not ln.strip().startswith("d") and ":" in ln
                ]
                log(f"App data dir: {len(paths)} file entries found.")
                return paths
            else:
                log(f"App data dir empty or inaccessible: {data_dir}")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"pkg_files capture failed: {exc}")
        return []

    def _capture_appops(
        self, pkg_name: str, adb: str, tools_dir: Path, log: Callable
    ) -> str:
        """Capture appops permission usage snapshot after runtime."""
        try:
            appops_dir = tools_dir / "adb_appops"
            appops_dir.mkdir(parents=True, exist_ok=True)
            code, out, _ = run_command_capture(
                [adb, "shell", "appops", "get", pkg_name],
                timeout=self.config.adb_timeout_sec,
            )
            appops_path = appops_dir / "appops_after_runtime.txt"
            if code == 0 and out.strip():
                appops_path.write_text(out, encoding="utf-8", errors="replace")
                log(f"appops snapshot saved → {appops_path}")
                return str(appops_path)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"appops capture failed: {exc}")
        return ""

    def _detect_crash(self, logcat_path: str, pkg_name: str) -> dict:
        """Scan full logcat for FATAL EXCEPTION in target package."""
        if not logcat_path or not Path(logcat_path).exists():
            return {}
        try:
            text = Path(logcat_path).read_text(encoding="utf-8", errors="replace")
        except Exception:  # pylint: disable=broad-exception-caught
            return {}

        # Pattern: FATAL EXCEPTION + Process: <pkg> in nearby lines
        pattern = re.compile(
            r"FATAL EXCEPTION[^\n]*\n(?:.*\n){0,3}.*Process:\s*" + re.escape(pkg_name),
            re.MULTILINE,
        )
        match = pattern.search(text)
        if match:
            start = max(0, match.start())
            end = min(len(text), match.end() + 800)
            return {"detected": True, "snippet": text[start:end][:1200]}

        # Simpler fallback
        if f"Process: {pkg_name}" in text and "FATAL EXCEPTION" in text:
            return {"detected": True, "snippet": ""}

        return {}

    def _build_findings(
        self,
        pkg_name: str,
        app_pid: str,
        pid_logcat_out: str,
        pid_logcat_empty: bool,
        pkg_files: list[str],
        coverage_pct: float,
        app_crashed: bool,
        crash_time: str,
        crash_info: dict,
        actual_duration: float,
        net_alerts: list[dict],
        appops_path: str = "",
    ) -> list[Stage2Finding]:
        findings: list[Stage2Finding] = []

        # ---- §14.3 Coverage gate (suppress requires-triggering findings) ----
        low_coverage = coverage_pct >= 0 and coverage_pct < 0.30
        # ---- §14.3 Duration gate (selective) --------------------------------
        too_short = actual_duration < 30

        # info_low_exerciser_coverage
        if coverage_pct >= 0 and coverage_pct < 0.50:
            findings.append(Stage2Finding(
                finding_id="info_low_exerciser_coverage",
                confidence="C1",
                title=f"Low exerciser coverage ({coverage_pct:.0%})",
                detail=(
                    f"UiExerciser completed {coverage_pct:.0%} of configured events. "
                    "Negative findings (no NDV observed) have reduced confidence. "
                    + ("Coverage <20%: all negative findings are unreliable." if coverage_pct < 0.20 else "")
                ),
            ))

        # info_app_crashed_during_exercise (NOT suppressed by duration gate)
        if app_crashed:
            detail = f"App process died during capture window."
            if crash_time:
                detail += f" PID disappeared at {crash_time}."
            if crash_info.get("snippet"):
                snippet = crash_info["snippet"][:300].replace("\n", " ")
                detail += f" Crash snippet: {snippet}"
            findings.append(Stage2Finding(
                finding_id="info_app_crashed_during_exercise",
                confidence="C1",
                title="App process died during exercise window",
                detail=detail,
                evidence=pid_logcat_out or "",
            ))

        # info_app_produced_no_logcat
        # §14.3 Implementation gate: C2+ only when PID logcat is implemented
        if app_pid and pid_logcat_out:
            if pid_logcat_empty:
                findings.append(Stage2Finding(
                    finding_id="info_app_produced_no_logcat",
                    confidence="C1",
                    title="App produced no logcat output",
                    detail=(
                        "PID-filtered logcat stream is empty. App ran but emitted no log messages. "
                        "Possible: anti-analysis, NDK-only logging with custom tag, or immediate crash."
                    ),
                    evidence=pid_logcat_out,
                ))
        elif app_pid and not pid_logcat_out:
            # PID was resolved but no PID logcat started (shouldn't happen normally)
            pass
        # If no app_pid, app never launched — don't emit this finding

        # info_app_no_filesystem_writes
        # §14.3 Snapshot integrity gate: only if force-stop was called (always is now)
        if pkg_name and not pkg_files:
            suppressed = low_coverage
            findings.append(Stage2Finding(
                finding_id="info_app_no_filesystem_writes",
                confidence="C1",
                title="No files in app data directory after runtime",
                detail=(
                    f"No files found in /data/data/{pkg_name} after runtime. "
                    "App may operate in-memory only, store data server-side, or have crashed before writing."
                ),
                suppressed=suppressed,
                suppression_reason="Coverage <30%: snapshot evidence unreliable." if suppressed else "",
            ))

        # tshark alerts → findings (suppressed by duration gate where relevant)
        for alert in net_alerts:
            rule_id = alert.get("rule_id", "")
            f = Stage2Finding(
                finding_id=rule_id,
                confidence=alert.get("confidence", "C1"),
                title=alert.get("title", rule_id),
                detail=alert.get("detail", ""),
                evidence=alert.get("evidence", ""),
            )
            # Duration gate: suppress sustained-observation findings for short runs
            if too_short and rule_id in (
                "ndv_data_exfiltration_suspected",
                "backdoor_beacon_pattern",
                "sec_runtime_cleartext_transport",
            ):
                f.suppressed = True
                f.suppression_reason = f"Duration gate: run too short ({actual_duration:.0f}s < 30s)."
            findings.append(f)

        # Feature 4: appops findings (BIND_ACCESSIBILITY_SERVICE etc.)
        if appops_path:
            findings += self._parse_appops(appops_path)

        # Feature 5: suspicious native libraries from PID logcat
        if pid_logcat_out:
            findings += self._detect_suspicious_libs(pid_logcat_out)

        return findings

    # ------------------------------------------------------------------
    # Feature 4: appops parser
    # ------------------------------------------------------------------

    # Ops that are flagged when state is "allow" (post-runtime snapshot).
    # Format: op_name → (confidence, title_snippet)
    _SENSITIVE_APPOPS: dict[str, tuple[str, str]] = {
        "BIND_ACCESSIBILITY_SERVICE": (
            "C2",
            "Accessibility service binding active at runtime",
        ),
        "SYSTEM_ALERT_WINDOW": (
            "C1",
            "SYSTEM_ALERT_WINDOW permission used (overlay capability)",
        ),
        "WRITE_SETTINGS": (
            "C1",
            "WRITE_SETTINGS permission used at runtime",
        ),
        "PROCESS_OUTGOING_CALLS": (
            "C2",
            "PROCESS_OUTGOING_CALLS op active at runtime",
        ),
    }

    def _parse_appops(self, appops_path: str) -> list[Stage2Finding]:
        """Feature 4: parse appops snapshot and emit findings for sensitive allow-state ops."""
        try:
            text = Path(appops_path).read_text(encoding="utf-8", errors="replace")
        except Exception:  # pylint: disable=broad-exception-caught
            return []

        findings: list[Stage2Finding] = []
        for line in text.splitlines():
            stripped = line.strip()
            for op_name, (confidence, title) in self._SENSITIVE_APPOPS.items():
                if stripped.startswith(op_name + ":"):
                    state = stripped[len(op_name) + 1:].split(";")[0].strip().lower()
                    if state == "allow":
                        findings.append(Stage2Finding(
                            finding_id=f"perm_appops_{op_name.lower()}",
                            confidence=confidence,
                            title=title,
                            detail=(
                                f"AppOps snapshot shows {op_name} in state 'allow' after runtime. "
                                f"Raw entry: {stripped[:200]}"
                            ),
                            evidence=appops_path,
                        ))
        return findings

    # ------------------------------------------------------------------
    # Feature 5: suspicious native library detection
    # ------------------------------------------------------------------

    # Library name substrings considered suspicious + reason
    _SUSPICIOUS_LIB_PATTERNS: list[tuple[str, str]] = [
        ("libsqlcipher", "Encrypted SQLite (SQLCipher) — covert data storage"),
        ("libudt",       "UDT P2P protocol library — uncommon transport"),
        ("libshadowsocks", "Shadowsocks proxy library"),
        ("libfrida",     "Frida instrumentation library loaded by app"),
        ("libreflect",   "Reflection/hiding library"),
        ("libdexposed",  "Dexposed hooking framework"),
        ("libsubstrate", "Cydia Substrate hooking framework"),
    ]

    def _detect_suspicious_libs(self, pid_logcat_out: str) -> list[Stage2Finding]:
        """Feature 5: detect suspicious native .so files loaded by app process from PID logcat."""
        try:
            text = Path(pid_logcat_out).read_text(encoding="utf-8", errors="replace")
        except Exception:  # pylint: disable=broad-exception-caught
            return []

        found: list[tuple[str, str, str]] = []  # (lib_basename, reason, log_line)
        for line in text.splitlines():
            line_lower = line.lower()
            if ".so" not in line_lower:
                continue
            # linker / art load lines: "dlopen", "loaded native library", "opening zip"
            if not any(kw in line_lower for kw in ("dlopen", "loaded native", "opening zip", "linking")):
                continue
            for pattern, reason in self._SUSPICIOUS_LIB_PATTERNS:
                if pattern in line_lower:
                    lib_name = pattern + ".so"
                    if not any(lib_name == f[0] for f in found):
                        found.append((lib_name, reason, line.strip()[:200]))

        if not found:
            return []

        detail_lines = "; ".join(f"{lib} ({reason})" for lib, reason, _ in found)
        evidence_snippet = "\n".join(line for _, _, line in found[:5])
        return [Stage2Finding(
            finding_id="ndv_suspicious_native_libs",
            confidence="C2",
            title=f"Suspicious native library/libraries loaded: {', '.join(f[0] for f in found)}",
            detail=(
                f"App process loaded {len(found)} suspicious native library/libraries: {detail_lines}. "
                "Evidence from PID-filtered logcat linker messages."
            ),
            evidence=pid_logcat_out,
        )]

    def _get_package_name(self, apk_path: Path, run_dir: Path, log: Callable) -> str:
        # Try to read from Stage1 report
        try:
            project_dir = run_dir.parent.parent.parent
            for report_path in sorted(project_dir.rglob("stage1_report.json"), reverse=True):
                try:
                    data = json.loads(report_path.read_text(encoding="utf-8"))
                    pkg = data.get("project", {}).get("package_name")
                    if pkg:
                        return pkg
                except Exception:  # pylint: disable=broad-exception-caught
                    continue
        except Exception:  # pylint: disable=broad-exception-caught
            pass

        # Fallback: aapt2
        try:
            code, out, _ = run_command_capture(
                ["aapt2", "dump", "badging", str(apk_path)],
                timeout=30,
            )
            if code == 0:
                for line in out.splitlines():
                    if line.startswith("package:"):
                        for part in line.split():
                            if part.startswith("name="):
                                return part.split("=", 1)[1].strip("'\"")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"Package name detection failed: {exc}")

        return ""
