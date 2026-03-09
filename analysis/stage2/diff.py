from __future__ import annotations

import subprocess
import tarfile
from pathlib import Path
from typing import Callable

from analysis.models.stage2 import Stage2DiffResult, Stage2Snapshot


class SnapshotDiff:
    def __init__(self, on_log: Callable[[str], None] | None = None) -> None:
        self._log = on_log or (lambda m: None)

    def compute(
        self,
        snap_a: Stage2Snapshot,
        snap_b: Stage2Snapshot,
        out_dir: Path,
    ) -> Stage2DiffResult:
        out_dir.mkdir(parents=True, exist_ok=True)
        result = Stage2DiffResult()

        # Packages diff
        if snap_a.packages_path and snap_b.packages_path:
            pkg_diff_path = out_dir / f"diff_packages_{snap_a.tag}_vs_{snap_b.tag}.txt"
            self._log(f"Computing package diff ({snap_a.tag} → {snap_b.tag})...")
            diff_out = self._run_diff(snap_a.packages_path, snap_b.packages_path)
            pkg_diff_path.write_text(diff_out, encoding="utf-8")
            result.packages_diff_path = str(pkg_diff_path)
            result.new_packages = self._parse_new_packages(diff_out)

        # Filesystem diff
        if snap_a.fs_tar_path and snap_b.fs_tar_path:
            fs_diff_path = out_dir / f"diff_fs_{snap_a.tag}_vs_{snap_b.tag}.txt"
            self._log(f"Computing filesystem diff ({snap_a.tag} → {snap_b.tag})...")
            dir_a = out_dir / f"fs_{snap_a.tag}"
            dir_b = out_dir / f"fs_{snap_b.tag}"
            self._extract_tar(snap_a.fs_tar_path, dir_a)
            self._extract_tar(snap_b.fs_tar_path, dir_b)
            diff_out = self._run_diff_dirs(str(dir_a), str(dir_b))
            fs_diff_path.write_text(diff_out, encoding="utf-8")
            result.fs_diff_path = str(fs_diff_path)
            result.new_paths = self._parse_new_paths(diff_out)

        return result

    def _run_diff(self, path_a: str, path_b: str) -> str:
        try:
            proc = subprocess.run(
                ["diff", "-u", path_a, path_b],
                capture_output=True, text=True, timeout=30,
            )
            return proc.stdout
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return f"# diff error: {exc}\n"

    def _run_diff_dirs(self, dir_a: str, dir_b: str) -> str:
        try:
            proc = subprocess.run(
                ["diff", "-ru", "--no-dereference", dir_a, dir_b],
                capture_output=True, text=False, timeout=120,
            )
            # Use errors="replace" so binary files (SQLite, DEX, etc.) don't crash decode
            return proc.stdout.decode("utf-8", errors="replace")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return f"# diff error: {exc}\n"

    def _extract_tar(self, tar_path: str, out_dir: Path) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            with tarfile.open(tar_path, "r:*") as tar:
                tar.extractall(path=str(out_dir))  # noqa: S202
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"tar extract warning ({tar_path}): {exc}")

    def _parse_new_packages(self, diff_out: str) -> list[str]:
        result = []
        for line in diff_out.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                pkg = line[1:].strip()
                if pkg.startswith("package:"):
                    result.append(pkg[len("package:"):].strip())
        return result

    def _parse_new_paths(self, diff_out: str) -> list[str]:
        result = []
        for line in diff_out.splitlines():
            if line.startswith("+++ ") and not line.startswith("+++ /dev/null"):
                path = line[4:].strip()
                if path.startswith("b/"):
                    path = path[2:]
                result.append(path)
        return result[:100]
