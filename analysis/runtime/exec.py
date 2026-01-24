from __future__ import annotations

import os
import signal
import threading
import subprocess
import time
from pathlib import Path
from typing import Any, Callable


def run_command_capture(
    cmd: list[str],
    cwd: Path | None = None,
    env: dict[str, Any] | None = None,
    timeout: float | None = None,
    terminate_timeout: float = 2.0,
    stdout_cb: Callable[[str], None] | None = None,
    stderr_cb: Callable[[str], None] | None = None,
    kill_process_group: bool = False,
) -> tuple[int, str, str]:
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    timed_out = False

    def _reader(stream, chunks: list[str], callback: Callable[[str], None] | None) -> None:
        for line in iter(stream.readline, ""):
            chunks.append(line)
            if callback:
                callback(line.rstrip("\n"))
        stream.close()

    start_new_session = kill_process_group and os.name == "posix"
    process = subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        start_new_session=start_new_session,
    )
    threads: list[threading.Thread] = []
    if process.stdout:
        thread = threading.Thread(
            target=_reader, args=(process.stdout, stdout_chunks, stdout_cb), daemon=True
        )
        thread.start()
        threads.append(thread)
    if process.stderr:
        thread = threading.Thread(
            target=_reader, args=(process.stderr, stderr_chunks, stderr_cb), daemon=True
        )
        thread.start()
        threads.append(thread)

    def _group_exists(pid: int) -> bool:
        try:
            os.killpg(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def _terminate_group(pid: int) -> None:
        if os.name != "posix":
            process.terminate()
            return
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        except PermissionError:
            return
        end = time.time() + terminate_timeout
        while time.time() < end:
            if not _group_exists(pid):
                return
            time.sleep(0.05)
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            return

    def _terminate_process() -> None:
        if kill_process_group and process.pid:
            _terminate_group(process.pid)
            return
        process.terminate()

    def _kill_process() -> None:
        if kill_process_group and process.pid:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    return
                except PermissionError:
                    return
            else:
                process.kill()
            return
        process.kill()

    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process()
        try:
            process.wait(timeout=terminate_timeout)
        except subprocess.TimeoutExpired:
            _kill_process()
            process.wait()

    if kill_process_group and process.returncode not in (0, None):
        if process.pid:
            _terminate_group(process.pid)

    for thread in threads:
        thread.join()

    stdout = "".join(stdout_chunks)
    stderr = "".join(stderr_chunks)
    if timed_out:
        raise subprocess.TimeoutExpired(cmd, timeout, output=stdout, stderr=stderr)
    return process.returncode or 0, stdout or "", stderr or ""
