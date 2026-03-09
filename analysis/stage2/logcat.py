from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable

from analysis.runtime.exec import run_command_capture
from analysis.stage2._sdk import find_sdk_bin


class LogcatCapture:
    def __init__(
        self,
        adb_timeout_sec: int = 30,
        on_log: Callable[[str], None] | None = None,
    ) -> None:
        self.adb_timeout_sec = adb_timeout_sec
        self._log = on_log or (lambda m: None)
        # Full-device logcat
        self._proc: subprocess.Popen | None = None  # type: ignore[type-arg]
        self._log_path: Path | None = None
        self._out_file = None
        # PID-filtered logcat
        self._proc_pid: subprocess.Popen | None = None  # type: ignore[type-arg]
        self._pid_log_path: Path | None = None
        self._pid_out_file = None

    def start(self, out_path: Path) -> None:
        adb = find_sdk_bin("adb")
        self._log_path = out_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        # Clear logcat buffer first
        run_command_capture([adb, "logcat", "-c"], timeout=self.adb_timeout_sec)
        self._log(f"Starting logcat capture → {out_path}")
        self._out_file = out_path.open("w", encoding="utf-8", errors="replace")
        self._proc = subprocess.Popen(
            [adb, "logcat"],
            stdout=self._out_file,
            stderr=subprocess.DEVNULL,
        )

    def start_pid_filter(self, pid: str, out_path: Path) -> None:
        """Start a second parallel logcat stream filtered to a specific PID.

        This gives exact app attribution: every line in the resulting file
        is from the target process, regardless of the log tag used.
        If the app produces no output, the file will be empty — which is
        itself a C1 indicator (info_app_produced_no_logcat).
        """
        if not pid:
            return
        adb = find_sdk_bin("adb")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        self._pid_log_path = out_path
        self._pid_out_file = out_path.open("w", encoding="utf-8", errors="replace")
        self._proc_pid = subprocess.Popen(
            [adb, "logcat", f"--pid={pid}"],
            stdout=self._pid_out_file,
            stderr=subprocess.DEVNULL,
        )
        self._log(f"Starting PID-filtered logcat (pid={pid}) → {out_path}")

    def stop(self) -> tuple[str, str]:
        """Stop both logcat streams.

        Returns:
            (full_logcat_path, pid_logcat_path) — either may be empty string
            if the corresponding stream was not started.
        """
        for proc_attr in ("_proc", "_proc_pid"):
            proc = getattr(self, proc_attr, None)
            if proc is not None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:  # pylint: disable=broad-exception-caught
                    proc.kill()
                setattr(self, proc_attr, None)

        for file_attr in ("_out_file", "_pid_out_file"):
            f = getattr(self, file_attr, None)
            if f is not None:
                try:
                    f.close()
                except Exception:  # pylint: disable=broad-exception-caught
                    pass
                setattr(self, file_attr, None)

        self._log("Logcat capture stopped.")
        return (
            str(self._log_path) if self._log_path else "",
            str(self._pid_log_path) if self._pid_log_path else "",
        )
