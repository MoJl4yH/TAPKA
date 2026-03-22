from __future__ import annotations

import json
import re
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
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


@dataclass
class _ManifestData:
    """Manifest components extracted from Stage 1 report / AndroidManifest.xml."""
    exported_activities: list[str] = field(default_factory=list)
    exported_receivers: list[str] = field(default_factory=list)
    deeplinks: list[str] = field(default_factory=list)  # fully constructed URIs


def _load_manifest_data(project_dir: Path) -> _ManifestData:
    """Load exported components and deeplinks from Stage 1 artifacts.

    First reads exported activities/receivers from stage1_report.json sections,
    then parses AndroidManifest.xml (apktool output) for deeplink URIs.
    """
    result = _ManifestData()

    # --- exported activities + receivers from stage1_report.json ---
    try:
        for report_path in sorted(project_dir.rglob("stage1_report.json"), reverse=True):
            try:
                data = json.loads(report_path.read_text(encoding="utf-8"))
                for section in data.get("sections", []):
                    if section.get("id") != "manifest":
                        continue
                    for item in section.get("data", {}).get("exported", []):
                        tag, _, name = str(item).partition(":")
                        if tag == "activity" and name:
                            result.exported_activities.append(name)
                        elif tag == "receiver" and name:
                            result.exported_receivers.append(name)
                if result.exported_activities or result.exported_receivers:
                    break
            except Exception:  # pylint: disable=broad-exception-caught
                continue
    except Exception:  # pylint: disable=broad-exception-caught
        pass

    # --- deeplinks from AndroidManifest.xml ---
    try:
        _NS = "http://schemas.android.com/apk/res/android"
        for manifest_path in sorted(project_dir.rglob("AndroidManifest.xml"), reverse=True):
            if "out_apktool" not in str(manifest_path):
                continue
            try:
                tree = ET.parse(manifest_path)
                root = tree.getroot()
                for intent_filter in root.iter("intent-filter"):
                    actions = [
                        e.get(f"{{{_NS}}}name", "") for e in intent_filter.findall("action")
                    ]
                    categories = [
                        e.get(f"{{{_NS}}}name", "") for e in intent_filter.findall("category")
                    ]
                    has_view = any(
                        a == "android.intent.action.VIEW" or a.endswith(".VIEW")
                        for a in actions
                    )
                    has_browsable = any(
                        c == "android.intent.category.BROWSABLE" or c.endswith(".BROWSABLE")
                        for c in categories
                    )
                    if not (has_view or has_browsable):
                        continue
                    for data_el in intent_filter.findall("data"):
                        scheme = data_el.get(f"{{{_NS}}}scheme", "")
                        host = data_el.get(f"{{{_NS}}}host", "")
                        path = data_el.get(f"{{{_NS}}}path", "") or data_el.get(
                            f"{{{_NS}}}pathPrefix", ""
                        )
                        if scheme:
                            uri = f"{scheme}://{host}{path}" if host else f"{scheme}://"
                            if uri not in result.deeplinks:
                                result.deeplinks.append(uri)
                break
            except Exception:  # pylint: disable=broad-exception-caught
                continue
    except Exception:  # pylint: disable=broad-exception-caught
        pass

    return result


def _parse_permissions(dumpsys_pkg_txt: str) -> dict[str, list[str]]:
    """Parse requested/granted/denied permissions from 'dumpsys package <pkg>' output."""
    requested: list[str] = []
    granted: list[str] = []
    denied: list[str] = []

    in_requested = False
    in_runtime = False
    for line in dumpsys_pkg_txt.splitlines():
        stripped = line.strip()
        if "requested permissions:" in stripped.lower():
            in_requested = True
            in_runtime = False
            continue
        if "install permissions:" in stripped.lower() or "runtime permissions:" in stripped.lower():
            in_requested = False
            in_runtime = True
            continue
        if stripped and not stripped[0].isalpha() and in_requested:
            # permission lines are indented
            perm = stripped.split(":")[0].strip()
            if perm.startswith("android.permission.") or "." in perm:
                requested.append(perm)
        if in_runtime and ":" in stripped:
            perm, _, rest = stripped.partition(":")
            perm = perm.strip()
            if perm.startswith("android.permission.") or "." in perm:
                if "granted=true" in rest:
                    granted.append(perm)
                elif "granted=false" in rest:
                    denied.append(perm)
        # Stop at next top-level section
        if stripped.startswith("User ") or stripped.startswith("Package ["):
            in_requested = False
            in_runtime = False

    return {"requested": sorted(set(requested)), "granted": sorted(set(granted)),
            "denied": sorted(set(denied))}


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
        log("Запущен этап 2: динамический анализ.")

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
            cpu_cores=self.config.emulator_cpu_cores,
        )
        snap = SystemSnapshot(adb_timeout_sec=self.config.adb_timeout_sec, on_log=log)
        installer = ApkInstaller(adb_timeout_sec=self.config.adb_timeout_sec, on_log=log)
        differ = SnapshotDiff(on_log=log)
        logcat = LogcatCapture(adb_timeout_sec=self.config.adb_timeout_sec, on_log=log)
        traffic = TrafficCapture(adb_timeout_sec=self.config.adb_timeout_sec, on_log=log)
        zeek = ZeekAnalyzer(on_log=log)

        tools_index: list[dict] = []
        traffic_started = False
        pcap_pulled = False
        _mitm_proc = None
        emulator_serial = ""
        pkg_name = ""
        app_uid = ""
        app_pid = ""
        pid_monitor: _PidMonitor | None = None
        exerciser_sent = 0
        exerciser_total = 0
        run_start_ts = time.monotonic()
        capture_end_ts = run_start_ts  # will be updated after traffic capture

        try:
            # ----------------------------------------------------------------
            # Step 1: Start emulator
            # ----------------------------------------------------------------
            boot_start = time.monotonic()
            log("Шаг 1: запуск эмулятора...")
            emulator.start(headless=True, writable_system=self.config.enable_https_interception)
            booted = emulator.wait_boot(timeout_sec=self.config.emulator_boot_timeout_sec)
            if not booted:
                raise RuntimeError(
                    f"Эмулятор не загрузился за {self.config.emulator_boot_timeout_sec} с. "
                    "Убедитесь, что KVM доступен и AVD создан."
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
            log(f"Эмулятор готов через {boot_time} с.")

            # ----------------------------------------------------------------
            # Step 2: Resolve package name (before baseline snapshot so scope
            #         matches between before/after snapshots)
            # ----------------------------------------------------------------
            pkg_name = self._get_package_name(apk_path, run_dir, log)
            log(f"Имя пакета: {pkg_name or '(неизвестно)'}")

            # ----------------------------------------------------------------
            # Step 2: Baseline snapshot (scoped to package when known)
            # ----------------------------------------------------------------
            log("Шаг 2: снятие базового снимка...")
            snap_before = snap.capture("before", snap_dir, package_name=pkg_name)

            # ----------------------------------------------------------------
            # Step 3: APK install → resolve UID
            # ----------------------------------------------------------------
            log("Шаг 3: установка APK...")
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
                raise RuntimeError(f"Не удалось установить APK (exit={install_code}).")

            if pkg_name:
                app_uid = self._resolve_uid(pkg_name, adb, log)
                if app_uid:
                    log(f"UID приложения: {app_uid}")

            # ----------------------------------------------------------------
            # Step 4: Post-install snapshot
            # ----------------------------------------------------------------
            log("Шаг 4: снимок после установки...")
            snap_after_install = snap.capture("after_install", snap_dir, package_name=pkg_name)

            # ----------------------------------------------------------------
            # Step 5: Install diff
            # ----------------------------------------------------------------
            log("Шаг 5: вычисление различий после установки...")
            install_diff = differ.compute(snap_before, snap_after_install, diffs_dir)
            stage2_data["install_diff"] = {
                "new_packages": install_diff.new_packages,
                "new_paths": install_diff.new_paths[:50],
                "fs_diff_path": install_diff.fs_diff_path,
                "packages_diff_path": install_diff.packages_diff_path,
            }

            # ----------------------------------------------------------------
            # Step 5.5: HTTPS interception via mitmproxy (optional)
            # ----------------------------------------------------------------
            if self.config.enable_https_interception:
                from analysis.stage2.mitm import (  # noqa: PLC0415
                    install_mitm_ca_to_emulator,
                    set_emulator_proxy,
                    start_mitmproxy,
                )
                try:
                    emulator_serial = self._resolve_emulator_serial(adb)
                    install_mitm_ca_to_emulator(emulator_serial, on_progress=log)
                    set_emulator_proxy(
                        emulator_serial, port=self.config.mitm_port, on_progress=log
                    )
                    mitm_dump = (
                        Path(self.config.mitm_dump_path)
                        if self.config.mitm_dump_path
                        else None
                    )
                    _mitm_proc = start_mitmproxy(
                        port=self.config.mitm_port, dump_path=mitm_dump
                    )
                    log("HTTPS-перехват активирован через mitmproxy")
                except Exception as _mitm_exc:  # pylint: disable=broad-exception-caught
                    log(f"[WARN] mitmproxy не запущен: {_mitm_exc}")
                    _mitm_proc = None

            # ----------------------------------------------------------------
            # Step 6: Start logcat + traffic capture
            # NOTE: Traffic capture starts AFTER APK installation. Any network
            # activity during install-time (Step 3) is NOT captured in the PCAP.
            # ----------------------------------------------------------------
            log("Шаг 6: запуск сбора logcat и сетевого трафика...")
            logcat_path = tools_dir / "adb_logcat" / "logcat_runtime.txt"
            t_runtime_start = now_utc_iso()
            logcat.start(logcat_path)
            pcap_local = tools_dir / "adb_traffic" / "traffic_runtime.pcap"
            traffic_started = traffic.start()

            # ----------------------------------------------------------------
            # Step 7: Launch app → resolve PID → start PID logcat + monitor
            # ----------------------------------------------------------------
            exerciser: UiExerciser | None = None
            project_dir = run_dir.parent.parent.parent
            manifest_data = _load_manifest_data(project_dir)

            if pkg_name:
                log(f"Шаг 7: запуск приложения ({pkg_name})...")
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

                # ------------------------------------------------------------
                # Step 7a: Launch exported Activities via am start
                # Runs after monkey starts so both generate traffic concurrently.
                # First pass gives proxy-captured traffic + logcat coverage.
                # ------------------------------------------------------------
                if self.config.activity_fuzz and manifest_data.exported_activities:
                    acts = manifest_data.exported_activities
                    log(f"Запуск exported Activities ({len(acts)} шт.)...")
                    act_dir = tools_dir / "adb_activities"
                    act_dir.mkdir(parents=True, exist_ok=True)
                    act_results: list[str] = []
                    for act in acts:
                        try:
                            _, out, _ = run_command_capture(
                                [adb, "shell", "am", "start", "-n", f"{pkg_name}/{act}"],
                                timeout=self.config.adb_timeout_sec,
                            )
                            act_results.append(f"{act}: {(out or '').strip()[:120]}")
                        except subprocess.TimeoutExpired:
                            act_results.append(f"{act}: TIMEOUT")
                            log(f"[WARN] am start {act}: timeout")
                        time.sleep(2)
                    (act_dir / "activity_launch_results.txt").write_text(
                        "\n".join(act_results), encoding="utf-8"
                    )
                    log(f"Exported Activities: {len(act_results)} запущено.")

                # ------------------------------------------------------------
                # Step 7b: Deeplink fuzzing via am start -d URI
                # ------------------------------------------------------------
                if self.config.deeplink_fuzz and manifest_data.deeplinks:
                    links = manifest_data.deeplinks
                    log(f"Deeplink fuzzing: {len(links)} URI...")
                    dl_dir = tools_dir / "adb_deeplinks"
                    dl_dir.mkdir(parents=True, exist_ok=True)
                    dl_results: list[str] = []
                    for uri in links:
                        try:
                            _, out, _ = run_command_capture(
                                [adb, "shell", "am", "start",
                                 "-a", "android.intent.action.VIEW",
                                 "-d", uri, pkg_name],
                                timeout=self.config.adb_timeout_sec,
                            )
                            dl_results.append(f"{uri}: {(out or '').strip()[:120]}")
                        except subprocess.TimeoutExpired:
                            dl_results.append(f"{uri}: TIMEOUT")
                            log(f"[WARN] deeplink {uri}: timeout")
                        time.sleep(2)
                    (dl_dir / "deeplink_fuzz.txt").write_text(
                        "\n".join(dl_results), encoding="utf-8"
                    )
                    log(f"Deeplink fuzzing: {len(dl_results)} URI отправлено.")

                # ------------------------------------------------------------
                # Step 7c: Intent fuzzing — am broadcast to exported receivers
                # + common system broadcast actions
                # ------------------------------------------------------------
                if self.config.intent_fuzz:
                    int_dir = tools_dir / "adb_intents"
                    int_dir.mkdir(parents=True, exist_ok=True)
                    int_results: list[str] = []

                    # Exported receivers by component name
                    for recv in manifest_data.exported_receivers:
                        try:
                            _, out, _ = run_command_capture(
                                [adb, "shell", "am", "broadcast",
                                 "-n", f"{pkg_name}/{recv}"],
                                timeout=self.config.adb_timeout_sec,
                            )
                            int_results.append(f"component {recv}: {(out or '').strip()[:120]}")
                        except subprocess.TimeoutExpired:
                            int_results.append(f"component {recv}: TIMEOUT")
                            log(f"[WARN] am broadcast {recv}: timeout")
                        time.sleep(1)

                    # Common system broadcast actions directed at the package.
                    # Protected broadcasts (BOOT_COMPLETED, CONNECTIVITY_CHANGE) are
                    # system-only senders — am broadcast hangs the full timeout before
                    # Android rejects them. Omitted intentionally.
                    _COMMON_ACTIONS = [
                        "android.intent.action.MY_PACKAGE_REPLACED",
                        "android.intent.action.USER_PRESENT",
                    ]
                    for action in _COMMON_ACTIONS:
                        try:
                            _, out, _ = run_command_capture(
                                [adb, "shell", "am", "broadcast",
                                 "-a", action, "-p", pkg_name],
                                timeout=self.config.adb_timeout_sec,
                            )
                            int_results.append(f"action {action}: {(out or '').strip()[:120]}")
                        except subprocess.TimeoutExpired:
                            int_results.append(f"action {action}: TIMEOUT")
                            log(f"[WARN] am broadcast {action}: timeout")
                        time.sleep(1)

                    if int_results:
                        (int_dir / "broadcast_results.txt").write_text(
                            "\n".join(int_results), encoding="utf-8"
                        )
                        log(f"Broadcast fuzzing: {len(int_results)} запросов отправлено.")

            else:
                log("Шаг 7: имя пакета не определено, запуск Monkey пропущен.")

            log(f"Выполняется захват в течение {self.config.runtime_duration_sec} с...")
            capture_start_ts = time.monotonic()  # window starts when exerciser is running

            # Monitoring loop — replaces bare time.sleep(runtime_duration_sec).
            # Detects early monkey exit and restarts the app + a new exerciser
            # for the remaining window so capture time is not wasted.
            _POLL_INTERVAL = 5
            deadline = time.monotonic() + self.config.runtime_duration_sec
            while time.monotonic() < deadline:
                time.sleep(min(_POLL_INTERVAL, max(0.0, deadline - time.monotonic())))
                if (
                    self.config.monkey_restart
                    and pkg_name
                    and exerciser is not None
                    and exerciser.is_done
                ):
                    remaining = deadline - time.monotonic()
                    if remaining > 30:
                        log(f"UiExerciser: завершился досрочно, перезапуск (осталось {remaining:.0f}s)...")
                        run_command_capture(
                            [adb, "shell", "monkey", "-p", pkg_name,
                             "-c", "android.intent.category.LAUNCHER", "1"],
                            timeout=self.config.adb_timeout_sec,
                        )
                        time.sleep(3)
                        exerciser = UiExerciser(
                            package=pkg_name,
                            duration_sec=int(remaining),
                            on_log=log,
                        )
                        exerciser.start()
                        exerciser_total += exerciser.events

            # ----------------------------------------------------------------
            # Step 8: Stop exerciser + monitors + logcat + traffic
            # ----------------------------------------------------------------
            log("Шаг 8: остановка UI-экзерсайзера, logcat и захвата трафика...")
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
                pcap_pulled = traffic.stop_and_pull(pcap_local)

            if _mitm_proc is not None:
                _mitm_proc.terminate()
                try:
                    from analysis.stage2.mitm import unset_emulator_proxy  # noqa: PLC0415
                    unset_emulator_proxy(emulator_serial)
                except Exception:  # pylint: disable=broad-exception-caught
                    pass

            capture_end_ts = time.monotonic()  # end of capture window (before post-processing)

            idx = write_tool_bundle(
                ctx, "adb_traffic",
                cmd=["adb", "shell", "tcpdump", "-i", "any", "-p", "-s", "0",
                     "-w", "/sdcard/traffic.pcap"],
                started_at=t_runtime_start,
                finished_at=t_runtime_end,
                exit_code=0 if pcap_pulled else 1,
                stdout="",
                stderr="" if traffic_started else "tcpdump not available on device",
                artifacts={"pcap": str(pcap_local)},
            )
            tools_index.append(idx)

            # ----------------------------------------------------------------
            # Step 8.5: Force-stop app before snapshot (flush DBs, release locks)
            # ----------------------------------------------------------------
            if pkg_name:
                log(f"Принудительная остановка {pkg_name} перед снятием снимка...")
                run_command_capture(
                    [adb, "shell", "am", "force-stop", pkg_name],
                    timeout=self.config.adb_timeout_sec,
                )
                time.sleep(1)  # brief wait for OS to flush

            # ----------------------------------------------------------------
            # Step 9: Post-runtime snapshot + diff
            # ----------------------------------------------------------------
            log("Шаг 9: снимок после выполнения и построение различий...")
            snap_after_runtime = snap.capture("after_runtime", snap_dir, package_name=pkg_name)
            runtime_diff = differ.compute(snap_after_install, snap_after_runtime, diffs_dir)

            # ----------------------------------------------------------------
            # Step 9.5: Target-package file listing + appops snapshot
            # ----------------------------------------------------------------
            pkg_files: list[str] = []
            appops_path = ""
            dumpsys_paths: dict[str, str] = {}
            permissions_diff: dict[str, list[str]] = {}
            if pkg_name:
                pkg_files = self._capture_pkg_files(pkg_name, adb, tools_dir, log)
                appops_path = self._capture_appops(pkg_name, adb, tools_dir, log)

                # --------------------------------------------------------
                # Step 9.6: Dumpsys collection (package / activity / battery)
                # --------------------------------------------------------
                if self.config.collect_dumpsys:
                    log("Сбор dumpsys (package/activity/battery)...")
                    dumpsys_dir = tools_dir / "adb_dumpsys"
                    dumpsys_dir.mkdir(parents=True, exist_ok=True)
                    dumpsys_targets = [
                        (["dumpsys", "package", pkg_name], "dumpsys_package.txt"),
                        (["dumpsys", "activity", "activities"], "dumpsys_activities.txt"),
                        (["dumpsys", "battery"], "dumpsys_battery.txt"),
                    ]
                    for subcmd, fname in dumpsys_targets:
                        _, out, _ = run_command_capture(
                            [adb, "shell"] + subcmd,
                            timeout=self.config.adb_timeout_sec,
                        )
                        fpath = dumpsys_dir / fname
                        fpath.write_text(out or "", encoding="utf-8", errors="replace")
                        dumpsys_paths[fname] = str(fpath)
                    log(f"Dumpsys сохранён: {', '.join(dumpsys_paths.keys())}")

                # --------------------------------------------------------
                # Step 9.7: Permissions comparison (requested vs granted)
                # --------------------------------------------------------
                if self.config.collect_permissions:
                    pkg_dumpsys = dumpsys_paths.get("dumpsys_package.txt", "")
                    if pkg_dumpsys and Path(pkg_dumpsys).exists():
                        txt = Path(pkg_dumpsys).read_text(encoding="utf-8", errors="replace")
                        permissions_diff = _parse_permissions(txt)
                        perms_dir = tools_dir / "adb_permissions"
                        perms_dir.mkdir(parents=True, exist_ok=True)
                        perm_path = perms_dir / "permissions_diff.json"
                        perm_path.write_text(
                            json.dumps(permissions_diff, indent=2, ensure_ascii=False),
                            encoding="utf-8",
                        )
                        n_req = len(permissions_diff.get("requested", []))
                        n_gr = len(permissions_diff.get("granted", []))
                        n_dn = len(permissions_diff.get("denied", []))
                        log(f"Permissions: {n_req} requested, {n_gr} granted, {n_dn} denied.")

            stage2_data["runtime_diff"] = {
                "logcat_path": logcat_out,
                "pid_logcat_path": pid_logcat_out,
                "new_paths": runtime_diff.new_paths[:50],
                "fs_diff_path": runtime_diff.fs_diff_path,
                "target_pkg_files": pkg_files[:100],
                "target_pkg_files_count": len(pkg_files),
                "appops_path": appops_path,
                "dumpsys_paths": dumpsys_paths,
                "permissions_diff": permissions_diff,
            }

            # ----------------------------------------------------------------
            # Step 10: Zeek / tshark analysis (with TSV exports + alerts)
            # ----------------------------------------------------------------
            log("Шаг 10: анализ сетевого трафика средствами Zeek/tshark...")
            zeek_dir = tools_dir / "zeek"
            actual_duration = capture_end_ts - capture_start_ts
            net_capture = zeek.analyze(pcap_local, zeek_dir,
                                       capture_duration_sec=actual_duration)
            stage2_data["network"] = {
                "pcap_path": str(pcap_local),
                "pcap_pull_success": pcap_pulled,
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
                append_run_error(run, "Zeek/tshark не установлен; PCAP сохранён для ручного анализа.")

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

            stage1_findings, stage1_findings_path = self._load_stage1_findings(run_dir, log)
            stage2_data["correlation"] = self._correlate_with_stage1(
                stage1_findings=stage1_findings,
                stage1_findings_path=stage1_findings_path,
                appops_path=appops_path,
                runtime_new_paths=runtime_diff.new_paths,
                net_alerts=net_capture.alerts,
            )

        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"Этап 2 завершился ошибкой: {exc}")
            run.status = "Error"
            run.finished_at = now_utc_iso()  # UTC — fixes duration_sec bug
            append_run_error(run, f"Ошибка этапа 2: {exc}")
        else:
            run.status = "Done"
            run.finished_at = now_utc_iso()  # UTC — fixes duration_sec bug
            log("Этап 2 успешно завершён.")
        finally:
            # Step 11: Stop emulator (always)
            try:
                emulator.stop()
            except Exception as exc:  # pylint: disable=broad-exception-caught
                log(f"Ошибка при остановке эмулятора: {exc}")

        # Generate report
        try:
            report_manager = ReportManager(self.storage)
            _, html_path = report_manager.generate_stage2(run, run_dir, stage2_data)
            run.report_path = str(html_path)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"Не удалось сформировать отчёт: {exc}")

        write_run_finished(ctx, now_utc_iso(), tools_index)
        # BUG-06: persist run.status to run.json so reports can read it
        try:
            import json as _json  # noqa: PLC0415
            _run_path = ctx.run_dir / "run.json"
            if _run_path.exists():
                _data = _json.loads(_run_path.read_text(encoding="utf-8"))
                _data["status"] = run.status or "Done"
                _run_path.write_text(_json.dumps(_data, indent=2), encoding="utf-8")
        except (OSError, _json.JSONDecodeError):  # pylint: disable=broad-exception-caught
            pass
        log("Запуск этапа 2 финализирован.")
        return run

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_emulator_serial(self, adb: str) -> str:
        """Return the serial of the first connected Android device from adb devices."""
        try:
            _, out, _ = run_command_capture([adb, "devices"], timeout=10)
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "device":
                    return parts[0]
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        return "emulator-5554"

    def _resolve_uid(self, pkg_name: str, adb: str, log: Callable) -> str:
        """Resolve UID for installed package via pm list packages -U."""
        try:
            code, out, _ = run_command_capture(
                [adb, "shell", "pm", "list", "packages", "-U"],
                timeout=self.config.adb_timeout_sec,
            )
            if code == 0:
                for line in out.splitlines():
                    # Exact match: "package:com.foo uid:10209" — avoid substring hits on com.foo.bar
                    if line.startswith(f"package:{pkg_name} ") or line == f"package:{pkg_name}":
                        m = re.search(r"uid:(\d+)", line)
                        if m:
                            return m.group(1)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"Не удалось определить UID: {exc}")
        return ""

    def _resolve_pid(self, pkg_name: str, adb: str, log: Callable) -> str:
        """Resolve PID of running package via pidof, with retry for slow emulators."""
        for attempt in range(5):
            try:
                code, out, _ = run_command_capture(
                    [adb, "shell", "pidof", pkg_name],
                    timeout=self.config.adb_timeout_sec,
                )
                if code == 0:
                    pid = out.strip().split()[0] if out.strip() else ""
                    if pid:
                        log(f"PID приложения: {pid}")
                        return pid
            except Exception as exc:  # pylint: disable=broad-exception-caught
                log(f"Не удалось определить PID (попытка {attempt + 1}): {exc}")
            time.sleep(1)
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
                    and ":" in ln
                ]
                log(f"Каталог данных приложения: найдено {len(paths)} файловых записей.")
                return paths
            else:
                log(f"Каталог данных приложения пуст или недоступен: {data_dir}")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"Не удалось получить список файлов пакета: {exc}")
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
                log(f"Снимок appops сохранён → {appops_path}")
                return str(appops_path)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"Не удалось получить снимок appops: {exc}")
        return ""

    def _load_stage1_findings(self, run_dir: Path, log: Callable) -> tuple[list[dict], str]:
        """Load findings from the most recent Stage1 run for the same project."""
        try:
            project_dir = run_dir.parent.parent.parent
            candidates = sorted(project_dir.rglob("findings/findings.json"), reverse=True)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log(f"Не удалось найти Stage1 findings для корреляции: {exc}")
            return [], ""

        for path in candidates:
            if "stage1_static" not in str(path):
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:  # pylint: disable=broad-exception-caught
                log(f"Не удалось прочитать Stage1 findings ({path}): {exc}")
                continue
            if isinstance(payload, list):
                log(f"Для корреляции используются Stage1 findings: {path}")
                return payload, str(path)
        return [], ""

    def _read_appops_allowed_ops(self, appops_path: str) -> set[str]:
        if not appops_path:
            return set()
        try:
            text = Path(appops_path).read_text(encoding="utf-8", errors="replace")
        except Exception:  # pylint: disable=broad-exception-caught
            return set()

        allowed_ops: set[str] = set()
        for line in text.splitlines():
            stripped = line.strip()
            if ":" not in stripped:
                continue
            op_name, state = stripped.split(":", 1)
            if state.split(";", 1)[0].strip().lower() == "allow":
                allowed_ops.add(op_name.strip())
        return allowed_ops

    def _correlate_with_stage1(
        self,
        stage1_findings: list[dict],
        stage1_findings_path: str,
        appops_path: str,
        runtime_new_paths: list[str],
        net_alerts: list[dict],
    ) -> dict:
        """Correlate a limited set of Stage1 findings with existing Stage2 evidence."""
        correlation = {
            "source_stage1_findings_path": stage1_findings_path,
            "confirmed_indicators": [],
            "unconfirmed_indicators": [],
        }
        if not stage1_findings:
            return correlation

        allowed_ops = self._read_appops_allowed_ops(appops_path)
        runtime_paths = [path.lower() for path in runtime_new_paths]
        alert_ids = {
            str(alert.get("rule_id", "")).strip()
            for alert in net_alerts
            if isinstance(alert, dict)
        }

        unique_stage1_categories: list[str] = []
        seen_categories: set[str] = set()
        for finding in stage1_findings:
            if not isinstance(finding, dict):
                continue
            category = str(finding.get("category") or "").strip()
            if not category or category in seen_categories:
                continue
            seen_categories.add(category)
            unique_stage1_categories.append(category)

        rules = {
            "ndv_accessibility_surveillance": (
                lambda: "BIND_ACCESSIBILITY_SERVICE" in allowed_ops,
                "appops:BIND_ACCESSIBILITY_SERVICE=allow",
            ),
            "ndv_overlay_abuse": (
                lambda: "SYSTEM_ALERT_WINDOW" in allowed_ops,
                "appops:SYSTEM_ALERT_WINDOW=allow",
            ),
            "ndv_dynamic_code_loading_dex": (
                lambda: any(
                    path.endswith((".dex", ".jar", ".odex", ".vdex")) or ".dex" in path
                    for path in runtime_paths
                ),
                "runtime_diff:new_paths содержит DEX/JAR/ODEX",
            ),
            "sec_cleartext_http_endpoint": (
                lambda: "sec_runtime_cleartext_transport" in alert_ids,
                "network_alert:sec_runtime_cleartext_transport",
            ),
            "sec_cleartext_http_protocol": (
                lambda: "sec_runtime_cleartext_transport" in alert_ids,
                "network_alert:sec_runtime_cleartext_transport",
            ),
            # BUG-30: extended AppOps coverage
            "ndv_mic_eavesdropping": (
                lambda: "RECORD_AUDIO" in allowed_ops,
                "appops:RECORD_AUDIO=allow",
            ),
            "ndv_camera_surveillance": (
                lambda: "CAMERA" in allowed_ops,
                "appops:CAMERA=allow",
            ),
            "ndv_geo_tracking_foreground": (
                lambda: "ACCESS_FINE_LOCATION" in allowed_ops or "ACCESS_COARSE_LOCATION" in allowed_ops,
                "appops:ACCESS_FINE_LOCATION=allow or ACCESS_COARSE_LOCATION=allow",
            ),
            "ndv_geo_tracking_background": (
                lambda: "ACCESS_BACKGROUND_LOCATION" in allowed_ops,
                "appops:ACCESS_BACKGROUND_LOCATION=allow",
            ),
            "ndv_contacts_access": (
                lambda: "READ_CONTACTS" in allowed_ops,
                "appops:READ_CONTACTS=allow",
            ),
            "ndv_sms_intercept": (
                lambda: "READ_SMS" in allowed_ops or "RECEIVE_SMS" in allowed_ops,
                "appops:READ_SMS=allow or RECEIVE_SMS=allow",
            ),
            "ndv_sms_send": (
                lambda: "SEND_SMS" in allowed_ops,
                "appops:SEND_SMS=allow",
            ),
            # BUG-33: Stage2↔Stage1 correlation improvements
            "ndv_notification_listener": (
                lambda: "BIND_NOTIFICATION_LISTENER_SERVICE" in allowed_ops,
                "appops:BIND_NOTIFICATION_LISTENER_SERVICE=allow",
            ),
            "ndv_screen_capture_mediaprojection": (
                lambda: "PROJECT_MEDIA" in allowed_ops,
                "appops:PROJECT_MEDIA=allow",
            ),
        }

        for category in unique_stage1_categories:
            rule = rules.get(category)
            if rule is None:
                continue
            predicate, evidence = rule
            target_key = "confirmed_indicators" if predicate() else "unconfirmed_indicators"
            correlation[target_key].append({
                "category": category,
                "evidence": evidence,
            })

        return correlation

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
                title=f"Низкое покрытие UI-экзерсайзера ({coverage_pct:.0%})",
                detail=(
                    f"UI-экзерсайзер выполнил {coverage_pct:.0%} от заданного числа событий. "
                    "Отрицательные результаты (НДВ не наблюдались) имеют сниженную достоверность. "
                    + ("Покрытие <20%: всем отрицательным выводам нельзя доверять." if coverage_pct < 0.20 else "")
                ),
            ))

        # info_app_crashed_during_exercise (NOT suppressed by duration gate)
        if app_crashed:
            detail = f"Процесс приложения завершился в течение окна захвата."
            if crash_time:
                detail += f" PID исчез в {crash_time}."
            if crash_info.get("snippet"):
                snippet = crash_info["snippet"][:300].replace("\n", " ")
                detail += f" Фрагмент сбоя: {snippet}"
            findings.append(Stage2Finding(
                finding_id="info_app_crashed_during_exercise",
                confidence="C1",
                title="Процесс приложения завершился во время упражнения",
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
                    title="Приложение не сгенерировало сообщений в logcat",
                    detail=(
                        "Поток logcat, отфильтрованный по PID, пуст. Приложение выполнялось, но не вывело сообщений. "
                        "Возможные причины: антианализ, логирование только из NDK с нестандартным тегом или немедленный сбой."
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
                title="После выполнения отсутствуют файлы в каталоге данных приложения",
                detail=(
                    f"После выполнения не найдено файлов в /data/data/{pkg_name}. "
                    "Приложение может работать только в памяти, хранить данные на сервере или завершиться до записи на диск."
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
                f.suppression_reason = f"Ограничение по длительности: запуск слишком короткий ({actual_duration:.0f} с < 30 с)."
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
            "Во время выполнения активна привязка службы Accessibility",
        ),
        "SYSTEM_ALERT_WINDOW": (
            "C1",
            "Во время выполнения используется SYSTEM_ALERT_WINDOW (возможность оверлея)",
        ),
        "WRITE_SETTINGS": (
            "C1",
            "Во время выполнения используется WRITE_SETTINGS",
        ),
        "PROCESS_OUTGOING_CALLS": (
            "C2",
            "Во время выполнения активна операция PROCESS_OUTGOING_CALLS",
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
                                f"Снимок AppOps показывает, что {op_name} находится в состоянии 'allow' после выполнения. "
                                f"Необработанная запись: {stripped[:200]}"
                            ),
                            evidence=appops_path,
                        ))
        return findings

    # ------------------------------------------------------------------
    # Feature 5: suspicious native library detection
    # ------------------------------------------------------------------

    # Library name substrings considered suspicious + reason
    _SUSPICIOUS_LIB_PATTERNS: list[tuple[str, str]] = [
        ("libsqlcipher", "Зашифрованная SQLite (SQLCipher) — скрытое хранение данных"),
        ("libudt",       "Библиотека P2P-транспорта UDT — нестандартный протокол"),
        ("libshadowsocks", "Библиотека прокси Shadowsocks"),
        ("libfrida",     "Инструментальная библиотека Frida, загружена приложением"),
        ("libreflect",   "Библиотека рефлексии/сокрытия"),
        ("libdexposed",  "Фреймворк перехвата Dexposed"),
        ("libsubstrate", "Фреймворк перехвата Cydia Substrate"),
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
            title=f"Загружены подозрительные нативные библиотеки: {', '.join(f[0] for f in found)}",
            detail=(
                f"Процесс приложения загрузил {len(found)} подозрительных нативных библиотек: {detail_lines}. "
                "Основание: сообщения линковщика из потока logcat, отфильтрованного по PID."
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
            log(f"Не удалось определить имя пакета: {exc}")

        return ""
