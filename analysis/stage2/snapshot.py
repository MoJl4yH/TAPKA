from __future__ import annotations

from pathlib import Path
from typing import Callable

from analysis.models.stage2 import Stage2Snapshot
from analysis.runtime.exec import run_command_capture
from analysis.stage2._sdk import find_sdk_bin


class SystemSnapshot:
    def __init__(
        self,
        adb_timeout_sec: int = 30,
        on_log: Callable[[str], None] | None = None,
    ) -> None:
        self.adb_timeout_sec = adb_timeout_sec
        self._log = on_log or (lambda m: None)

    def capture(self, tag: str, out_dir: Path, package_name: str | None = None) -> Stage2Snapshot:
        adb = find_sdk_bin("adb")
        out_dir.mkdir(parents=True, exist_ok=True)
        snap = Stage2Snapshot(tag=tag)

        # 1. Package list
        pkg_path = out_dir / f"packages_{tag}.txt"
        self._log(f"Capturing package list (tag={tag})...")
        _, out, _ = run_command_capture(
            [adb, "shell", "pm", "list", "packages"],
            timeout=self.adb_timeout_sec,
        )
        pkg_path.write_text(out, encoding="utf-8")
        snap.packages_path = str(pkg_path)

        # 2. Filesystem tar — app-scoped when package_name is known, full /data/data otherwise
        remote_tar = f"/sdcard/fs_{tag}.tar"
        local_tar = out_dir / f"fs_{tag}.tar"
        self._log(f"Creating filesystem snapshot tar (tag={tag})...")
        if package_name:
            # Scope to package-specific directories to reduce noise.
            # Use list args (not shell string) to prevent shell injection via package_name.
            dirs = [
                f"/data/data/{package_name}",
                f"/sdcard/Android/data/{package_name}",
                f"/sdcard/Android/media/{package_name}",
            ]
            run_command_capture(
                [adb, "shell", "tar", "-cf", remote_tar] + dirs,
                timeout=self.adb_timeout_sec * 5,
            )
        else:
            run_command_capture(
                [adb, "shell", "tar", "-cf", remote_tar, "/data/data"],
                timeout=self.adb_timeout_sec * 5,
            )
        run_command_capture(
            [adb, "pull", remote_tar, str(local_tar)],
            timeout=self.adb_timeout_sec * 3,
        )
        # BUG-REL-02: clean up remote tar after pulling to free device storage
        run_command_capture(
            [adb, "shell", "rm", "-f", remote_tar],
            timeout=30,
        )
        if local_tar.exists():
            snap.fs_tar_path = str(local_tar)

        # 3. Network info
        net_path = out_dir / f"net_{tag}.txt"
        self._log(f"Capturing network info (tag={tag})...")
        _, addr_out, _ = run_command_capture(
            [adb, "shell", "ip", "addr"],
            timeout=self.adb_timeout_sec,
        )
        _, route_out, _ = run_command_capture(
            [adb, "shell", "ip", "route"],
            timeout=self.adb_timeout_sec,
        )
        net_path.write_text(addr_out + "\n" + route_out, encoding="utf-8")
        snap.net_info_path = str(net_path)

        self._log(f"Snapshot '{tag}' captured.")
        return snap
