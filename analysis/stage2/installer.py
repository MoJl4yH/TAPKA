from __future__ import annotations

from pathlib import Path
from typing import Callable

from analysis.runtime.exec import run_command_capture
from analysis.stage2._sdk import find_sdk_bin


class ApkInstaller:
    def __init__(
        self,
        adb_timeout_sec: int = 30,
        on_log: Callable[[str], None] | None = None,
    ) -> None:
        self.adb_timeout_sec = adb_timeout_sec
        self._log = on_log or (lambda m: None)

    def install(self, apk_path: Path, timeout_sec: int | None = None) -> tuple[int, str, str]:
        adb = find_sdk_bin("adb")
        timeout = timeout_sec or (self.adb_timeout_sec * 4)
        self._log(f"Installing APK: {apk_path}")

        # First attempt: include --bypass-low-target-sdk-block for old APKs on API 34+
        cmd = [adb, "install", "-r", "--bypass-low-target-sdk-block", str(apk_path)]
        code, stdout, stderr = run_command_capture(cmd, timeout=timeout)

        if code != 0 and "unknown option" in stderr.lower():
            # adb version doesn't support the flag — retry without it
            self._log("Retrying install without --bypass-low-target-sdk-block...")
            cmd = [adb, "install", "-r", str(apk_path)]
            code, stdout, stderr = run_command_capture(cmd, timeout=timeout)

        if code == 0:
            self._log("APK installed successfully.")
        else:
            self._log(f"APK install failed (exit={code}): {stderr.strip()[:200]}")
        return code, stdout, stderr
