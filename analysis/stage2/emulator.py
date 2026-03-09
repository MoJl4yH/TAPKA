from __future__ import annotations

import subprocess
import time
from typing import Callable

from analysis.runtime.exec import run_command_capture
from analysis.stage2._sdk import find_sdk_bin, sdk_env


class EmulatorManager:
    def __init__(
        self,
        avd_name: str = "tapka_api35",
        adb_timeout_sec: int = 30,
        on_log: Callable[[str], None] | None = None,
    ) -> None:
        self.avd_name = avd_name
        self.adb_timeout_sec = adb_timeout_sec
        self._log = on_log or (lambda m: None)
        self._proc: subprocess.Popen | None = None  # type: ignore[type-arg]

    def start(self, headless: bool = True) -> None:
        emulator_bin = find_sdk_bin("emulator")
        cmd = [
            emulator_bin, "-avd", self.avd_name,
            "-wipe-data", "-no-snapshot-save", "-no-boot-anim", "-netfast",
        ]
        if headless:
            cmd.append("-no-window")
        self._log(f"Starting emulator: {' '.join(cmd)}")
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=sdk_env(),
        )

    def wait_boot(self, timeout_sec: int = 180) -> bool:
        adb = find_sdk_bin("adb")
        self._log(f"Waiting for emulator boot (timeout={timeout_sec}s)...")
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            try:
                code, out, _ = run_command_capture(
                    [adb, "shell", "getprop", "sys.boot_completed"],
                    timeout=5,
                )
                if code == 0 and out.strip() == "1":
                    self._log("Emulator boot completed.")
                    return True
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            time.sleep(3)
        self._log("Emulator boot timed out.")
        return False

    def root(self) -> None:
        adb = find_sdk_bin("adb")
        self._log("Obtaining adb root...")
        run_command_capture([adb, "root"], timeout=self.adb_timeout_sec)
        run_command_capture([adb, "wait-for-device"], timeout=self.adb_timeout_sec)
        self._log("adb root obtained.")

    def stop(self) -> None:
        adb = find_sdk_bin("adb")
        self._log("Stopping emulator...")
        try:
            run_command_capture([adb, "emu", "kill"], timeout=self.adb_timeout_sec)
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=10)
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            self._proc = None
        self._log("Emulator stopped.")
