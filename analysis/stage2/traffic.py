from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Callable

from analysis.runtime.exec import run_command_capture
from analysis.stage2._sdk import find_sdk_bin

TCPDUMP_REMOTE_PATH = "/sdcard/traffic.pcap"
TCPDUMP_REMOTE_BIN = "/data/local/tmp/tcpdump"


class TrafficCapture:
    def __init__(
        self,
        adb_timeout_sec: int = 30,
        on_log: Callable[[str], None] | None = None,
    ) -> None:
        self.adb_timeout_sec = adb_timeout_sec
        self._log = on_log or (lambda m: None)
        self._proc: subprocess.Popen | None = None  # type: ignore[type-arg]

    def _ensure_tcpdump(self) -> str:
        """Return path to tcpdump on device; push static binary as fallback."""
        adb = find_sdk_bin("adb")
        _, out, _ = run_command_capture(
            [adb, "shell", "which tcpdump || echo NOTFOUND"],
            timeout=self.adb_timeout_sec,
        )
        path = out.strip()
        if path and path != "NOTFOUND" and "not found" not in path.lower():
            self._log(f"tcpdump found on device: {path}")
            return path

        local_bin = Path(os.path.expanduser("~")) / ".tapka" / "bin" / "tcpdump"
        if local_bin.exists():
            self._log(f"Pushing static tcpdump from {local_bin}...")
            run_command_capture(
                [adb, "push", str(local_bin), TCPDUMP_REMOTE_BIN],
                timeout=self.adb_timeout_sec * 2,
            )
            run_command_capture(
                [adb, "shell", f"chmod +x {TCPDUMP_REMOTE_BIN}"],
                timeout=self.adb_timeout_sec,
            )
            return TCPDUMP_REMOTE_BIN

        self._log("WARNING: tcpdump not found on device and no static binary in ~/.tapka/bin/tcpdump.")
        return ""

    def start(self) -> bool:
        adb = find_sdk_bin("adb")
        tcpdump_path = self._ensure_tcpdump()
        if not tcpdump_path:
            return False
        self._log("Starting tcpdump capture on device...")
        self._proc = subprocess.Popen(
            [adb, "shell", f"{tcpdump_path} -i any -p -s 0 -w {TCPDUMP_REMOTE_PATH}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True

    def stop_and_pull(self, local_path: Path) -> bool:
        adb = find_sdk_bin("adb")
        self._log("Stopping tcpdump and pulling pcap...")

        # Send SIGINT first so tcpdump flushes and closes the pcap properly.
        # Try multiple kill methods — availability varies by Android image.
        for kill_cmd in (
            "kill -2 $(pidof tcpdump) 2>/dev/null",    # SIGINT via pidof
            "killall -SIGINT tcpdump 2>/dev/null",       # killall (busybox)
            "pkill -SIGINT tcpdump 2>/dev/null",         # pkill
        ):
            try:
                run_command_capture(
                    [adb, "shell", kill_cmd],
                    timeout=self.adb_timeout_sec,
                )
            except Exception:  # pylint: disable=broad-exception-caught
                pass

        # Give tcpdump time to flush buffers and close the file
        import time  # noqa: PLC0415
        time.sleep(2)

        # Terminate the local adb shell wrapper process
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            self._proc = None

        local_path.parent.mkdir(parents=True, exist_ok=True)
        run_command_capture(
            [adb, "pull", TCPDUMP_REMOTE_PATH, str(local_path)],
            timeout=self.adb_timeout_sec * 3,
        )
        if local_path.exists():
            self._log(f"pcap pulled to {local_path}")
            return True
        self._log("WARNING: pcap file not found after pull.")
        return False
