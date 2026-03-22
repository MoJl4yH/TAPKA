from __future__ import annotations

import subprocess
import threading
from typing import Callable

from analysis.stage2._sdk import find_sdk_bin


class UiExerciser:
    """Exercises an installed APK during dynamic analysis using adb Monkey.

    Monkey is run as a background process so it generates UI events
    (taps, swipes, navigation) concurrently with logcat / tcpdump capture.
    A reader thread counts ":Sending" lines from Monkey's stdout and logs
    progress every ~10 % so it's visible that events are being sent.
    """

    def __init__(
        self,
        package: str,
        duration_sec: int,
        throttle_ms: int = 350,
        on_log: Callable[[str], None] | None = None,
    ) -> None:
        self.package = package
        self.throttle_ms = throttle_ms
        # events that roughly fill the duration; at least 20
        self.events = max(20, int(duration_sec * 1000 / throttle_ms))
        self._log = on_log or (lambda m: None)
        self._proc: subprocess.Popen | None = None  # type: ignore[type-arg]
        self._reader: threading.Thread | None = None
        self._sent: int = 0

    def start(self) -> bool:
        if not self.package:
            self._log("UiExerciser: no package name, skipping UI exercise.")
            return False

        adb = find_sdk_bin("adb")
        cmd = [
            adb, "shell", "monkey",
            "-p", self.package,
            "--throttle", str(self.throttle_ms),
            "--pct-touch", "40",
            "--pct-motion", "30",
            "--pct-nav", "10",
            "--pct-majornav", "10",
            "--pct-syskeys", "5",
            "--pct-appswitch", "0",
            "--pct-anyevent", "5",
            "--ignore-crashes",
            "--ignore-timeouts",
            "--ignore-security-exceptions",
            "-v",
            str(self.events),
        ]
        self._log(
            f"UiExerciser: starting {self.events} events "
            f"(throttle={self.throttle_ms}ms) on {self.package}..."
        )
        self._sent = 0
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        # Read monkey output in a daemon thread so we don't block the runner
        self._reader = threading.Thread(target=self._read_output, daemon=True)
        self._reader.start()
        return True

    def _read_output(self) -> None:
        if self._proc is None or self._proc.stdout is None:
            return

        # Report progress roughly every 10 %
        report_every = max(1, self.events // 10)

        for line in self._proc.stdout:
            line = line.strip()
            if ":Sending" in line:
                self._sent += 1
                if self._sent % report_every == 0:
                    pct = min(100, int(self._sent * 100 / self.events))
                    self._log(
                        f"UiExerciser: {self._sent}/{self.events} events sent ({pct}%)"
                    )
            elif line.startswith("// Monkey finished"):
                self._log(
                    f"UiExerciser: finished — {self._sent}/{self.events} events sent"
                )
            elif line.startswith("** Monkey aborted"):
                self._log(f"UiExerciser: aborted by Monkey — {line}")

    @property
    def is_done(self) -> bool:
        """True if monkey process has exited or was never started."""
        return self._proc is None or self._proc.poll() is not None

    def stop(self) -> None:
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            self._proc = None
        if self._reader is not None:
            self._reader.join(timeout=3)
            self._reader = None
        self._log(
            f"UiExerciser: stopped — {self._sent}/{self.events} events were sent."
        )
