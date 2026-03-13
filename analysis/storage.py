import hashlib
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from analysis.runtime.clock import now_utc_iso
from analysis.runtime.context import RunContext
from analysis.stages import STAGE_CROSS_TOOL, STAGE_DYNAMIC
from models import ApkMeta, Project, Run, Finding

class Storage:
    def __init__(self, workspace: str = "~/tapka_workspace"):
        self.workspace = Path(os.path.expanduser(workspace))
        self.projects_dir = self.workspace / "projects"
        self._ensure_dir(self.projects_dir)

    def _ensure_dir(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def list_projects(self) -> list[Project]:
        projects = []
        if not self.projects_dir.exists():
            return projects
        for project_dir in self.projects_dir.iterdir():
            if not project_dir.is_dir():
                continue
            project_json = project_dir / "project.json"
            if not project_json.exists():
                continue
            try:
                data = json.loads(project_json.read_text(encoding="utf-8"))
                projects.append(Project.model_validate(data))
            except (json.JSONDecodeError, ValueError, OSError):
                continue
        return sorted(projects, key=lambda p: p.created_at, reverse=True)

    def load_project(self, project_id: str) -> Project:
        project_json = self.get_project_dir(project_id) / "project.json"
        data = json.loads(project_json.read_text(encoding="utf-8"))
        return Project.model_validate(data)

    def create_project(self, apk_file: str) -> Project:
        apk_path = Path(apk_file)
        if not apk_path.is_file():
            raise FileNotFoundError(f"APK not found: {apk_file}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        sha256 = self.calculate_sha256(apk_path)
        project_id = self.generate_project_id(apk_path.name, sha256, timestamp=timestamp)
        project_dir = self.get_project_dir(project_id)
        if project_dir.exists():
            raise FileExistsError(f"Project already exists: {project_id}")

        versions_dir = project_dir / "versions"
        self._ensure_dir(versions_dir)

        safe_name = self._sanitize_name(apk_path.name)
        version_id = f"{timestamp}_{safe_name}_{sha256[:8]}"
        version_dir = versions_dir / version_id
        self._ensure_dir(version_dir / "apk")

        target = version_dir / "apk" / "original.apk"
        shutil.copy2(apk_path, target)

        rel_path = str(target.relative_to(project_dir))
        meta = self._build_apk_meta(apk_path.name, target, sha256, rel_path=rel_path)
        (version_dir / "meta.json").write_text(
            meta.model_dump_json(indent=2),
            encoding="utf-8",
        )

        project = Project(
            project_id=project_id,
            created_at=self._now(),
            apk_meta=meta,
            apk_versions=[meta],
            active_apk_sha256=meta.sha256,
        )
        (project_dir / "project.json").write_text(
            project.model_dump_json(indent=2),
            encoding="utf-8",
        )
        return project

    def create_project_with_name(self, project_id: str) -> Project:
        project_id = project_id.strip()
        if not project_id:
            raise ValueError("Project name cannot be empty.")
        if os.sep in project_id or (os.altsep and os.altsep in project_id):
            raise ValueError("Project name contains invalid path separators.")
        project_id = self._sanitize_name(project_id)
        if not project_id or project_id == "apk":
            raise ValueError("Project name is invalid after sanitization.")
        project_dir = self.get_project_dir(project_id)
        if project_dir.exists():
            raise FileExistsError(f"Project already exists: {project_id}")
        self._ensure_dir(project_dir / "versions")

        project = Project(project_id=project_id, created_at=self._now())
        (project_dir / "project.json").write_text(
            project.model_dump_json(indent=2),
            encoding="utf-8",
        )
        return project

    def add_apk_to_project(self, project_id: str, apk_file: str) -> Project:
        apk_path = Path(apk_file)
        if not apk_path.is_file():
            raise FileNotFoundError(f"APK not found: {apk_file}")

        project_dir = self.get_project_dir(project_id)
        if not project_dir.exists():
            raise FileNotFoundError(f"Project not found: {project_id}")

        versions_dir = project_dir / "versions"
        self._ensure_dir(versions_dir)

        sha256 = self.calculate_sha256(apk_path)
        project = self.load_project(project_id)
        project = self._ensure_project_versions(project, project_dir)
        if any(meta.sha256 == sha256 for meta in project.apk_versions):
            raise ValueError("The selected file is already present in the project.")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = self._sanitize_name(apk_path.name)
        version_id = f"{timestamp}_{safe_name}_{sha256[:8]}"
        version_dir = versions_dir / version_id
        self._ensure_dir(version_dir / "apk")
        target = version_dir / "apk" / "original.apk"
        shutil.copy2(apk_path, target)
        rel_path = str(target.relative_to(project_dir))
        meta = self._build_apk_meta(apk_path.name, target, sha256, rel_path=rel_path)

        project.apk_meta = meta
        project.apk_versions.append(meta)
        project.active_apk_sha256 = meta.sha256
        (project_dir / "project.json").write_text(
            project.model_dump_json(indent=2),
            encoding="utf-8",
        )
        (version_dir / "meta.json").write_text(
            meta.model_dump_json(indent=2),
            encoding="utf-8",
        )
        return project

    def generate_project_id(self, apk_name: str, sha256: str, timestamp: str | None = None) -> str:
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = self._sanitize_name(apk_name)
        return f"{timestamp}_{safe_name}_{sha256[:12]}"

    def generate_run_id(self, stage: str) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_stage = self._sanitize_name(stage)
        return f"{timestamp}_{safe_stage}"

    def _sanitize_name(self, name: str) -> str:
        base = name[:-4] if name.lower().endswith(".apk") else name
        base = re.sub(r"[^A-Za-z0-9._-]+", "_", base)
        base = base.strip("_")
        return base or "apk"

    def calculate_sha256(self, apk_file: Path) -> str:
        sha256_hash = hashlib.sha256()
        with apk_file.open("rb") as handle:
            for byte_block in iter(lambda: handle.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _build_apk_meta(
        self, apk_name: str, apk_copy: Path, sha256: str, rel_path: str | None = None
    ) -> ApkMeta:
        size = apk_copy.stat().st_size
        return ApkMeta(
            name=apk_name,
            sha256=sha256,
            size=size,
            imported_at=self._now(),
            path=rel_path,
        )

    def get_project_dir(self, project_id: str) -> Path:
        return self.projects_dir / project_id

    def delete_project(self, project_id: str) -> None:
        project_dir = self.get_project_dir(project_id)
        if not project_dir.exists():
            raise FileNotFoundError(f"Project not found: {project_id}")
        try:
            project_dir.resolve().relative_to(self.projects_dir.resolve())
        except (OSError, ValueError) as exc:
            raise ValueError("Refusing to delete path outside workspace.") from exc
        shutil.rmtree(project_dir)

    def get_apk_path(self, project_id: str) -> Path:
        project_dir = self.get_project_dir(project_id)
        project_json = project_dir / "project.json"
        if project_json.exists():
            try:
                data = json.loads(project_json.read_text(encoding="utf-8"))
                rel_path = (data.get("apk_meta") or {}).get("path")
                if rel_path:
                    return project_dir / rel_path
            except (json.JSONDecodeError, ValueError, OSError):
                pass
        return project_dir / "apk" / "original.apk"

    def get_active_version_dir(self, project_id: str) -> Path:
        project_dir = self.get_project_dir(project_id)
        try:
            project = self.load_project(project_id)
        except (FileNotFoundError, ValueError, OSError, json.JSONDecodeError):
            return project_dir
        project = self._ensure_project_versions(project, project_dir)
        if project.apk_meta and project.apk_meta.path:
            rel_path = Path(project.apk_meta.path)
            if "versions" in rel_path.parts:
                idx = rel_path.parts.index("versions")
                if idx + 1 < len(rel_path.parts):
                    return project_dir.joinpath(*rel_path.parts[: idx + 2])
        return project_dir

    def set_active_apk_version(self, project_id: str, sha256: str) -> Project:
        project_dir = self.get_project_dir(project_id)
        project = self.load_project(project_id)
        project = self._ensure_project_versions(project, project_dir)
        match = next((meta for meta in project.apk_versions if meta.sha256 == sha256), None)
        if not match:
            raise FileNotFoundError(f"APK version not found: {sha256}")
        project.apk_meta = match
        project.active_apk_sha256 = sha256
        (project_dir / "project.json").write_text(
            project.model_dump_json(indent=2),
            encoding="utf-8",
        )
        return project

    def _ensure_project_versions(self, project: Project, project_dir: Path) -> Project:
        if not project.apk_meta:
            return project
        if not project.apk_meta.path:
            default_path = project_dir / "apk" / "original.apk"
            rel_path = str(default_path.relative_to(project_dir))
            project.apk_meta = project.apk_meta.model_copy(update={"path": rel_path})
        if not project.apk_versions:
            project.apk_versions = [project.apk_meta]
        elif not any(meta.sha256 == project.apk_meta.sha256 for meta in project.apk_versions):
            project.apk_versions.insert(0, project.apk_meta)
        if not project.active_apk_sha256:
            project.active_apk_sha256 = project.apk_meta.sha256
        return project

    def create_run(self, project_id: str, stage: str) -> tuple[Run, Path]:
        run_id = self.generate_run_id(stage)
        run_dir = self.get_active_version_dir(project_id) / "runs" / run_id
        self._ensure_dir(run_dir / "logs")
        self._ensure_dir(run_dir / "artifacts" / "out_apktool")
        self._ensure_dir(run_dir / "artifacts" / "out_jadx")
        self._ensure_dir(run_dir / "artifacts" / "certs")
        self._ensure_dir(run_dir / "findings")
        self._ensure_dir(run_dir / "report")

        run = Run(
            run_id=run_id,
            project_id=project_id,
            stage=stage,
            started_at=self._now(),
            apk_path=str(self.get_apk_path(project_id)),
        )
        self.save_run(run, run_dir)
        return run, run_dir

    def save_run(self, run: Run, run_dir: Path) -> None:
        (run_dir / "run.json").write_text(
            run.model_dump_json(indent=2),
            encoding="utf-8",
        )

    def save_findings(self, run_dir: Path, findings: list[Finding]) -> Path:
        findings_path = run_dir / "findings" / "findings.json"
        payload = [finding.model_dump(mode="json") for finding in findings]
        findings_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return findings_path

    def get_run_dir(self, project_id: str, run_id: str) -> Path:
        return self.get_active_version_dir(project_id) / "runs" / run_id

    def get_latest_run(self, project_id: str, stage: str | None = None) -> tuple[Run, Path] | None:
        runs_dir = self.get_active_version_dir(project_id) / "runs"
        if not runs_dir.exists():
            return None
        run_dirs = [p for p in runs_dir.iterdir() if p.is_dir()]
        if not run_dirs:
            return None
        run_dirs.sort(key=lambda p: p.name, reverse=True)
        for run_dir in run_dirs:
            run_json = run_dir / "run.json"
            if not run_json.exists():
                continue
            try:
                data = json.loads(run_json.read_text(encoding="utf-8"))
                run = Run.model_validate(data)
            except (json.JSONDecodeError, ValueError, OSError):
                continue
            if stage and run.stage != stage:
                continue
            return run, run_dir
        return None

    def get_or_create_stage3_run(self, project_id: str) -> RunContext:
        project_dir = self.get_project_dir(project_id)
        version_dir = self.get_active_version_dir(project_id)
        runs_dir = version_dir / "runs"
        self._ensure_dir(runs_dir)
        apk_path = self.get_apk_path(project_id)
        # Always create a fresh run dir for Stage3 — each cross-tool run is independent.
        run_id = self.generate_run_id(STAGE_CROSS_TOOL)
        run_dir = runs_dir / run_id
        return RunContext(
            project_dir=project_dir,
            apk_path=apk_path,
            stage="stage3",
            run_id=run_id,
            run_dir=run_dir,
            started_at=now_utc_iso(),
        )

    def get_latest_stage2_run_dir(self, project_id: str) -> Path | None:
        """Return the most recent existing Stage2 run directory, or None."""
        version_dir = self.get_active_version_dir(project_id)
        runs_dir = version_dir / "runs"
        if not runs_dir.exists():
            return None
        suffix = f"_{STAGE_DYNAMIC}"
        run_dirs = [p for p in runs_dir.iterdir() if p.is_dir() and p.name.endswith(suffix)]
        if not run_dirs:
            return None
        run_dirs.sort(key=lambda p: p.name, reverse=True)
        return run_dirs[0]

    def get_or_create_stage2_run(self, project_id: str) -> RunContext:
        project_dir = self.get_project_dir(project_id)
        version_dir = self.get_active_version_dir(project_id)
        runs_dir = version_dir / "runs"
        self._ensure_dir(runs_dir)
        apk_path = self.get_apk_path(project_id)
        # Always create a fresh run dir for Stage2 — each dynamic run is independent.
        # (Reusing an existing dir would corrupt duration_sec and mix artifacts.)
        run_id = self.generate_run_id(STAGE_DYNAMIC)
        run_dir = runs_dir / run_id
        for sub in (
            "tools/adb_snapshot", "tools/adb_install", "tools/adb_logcat",
            "tools/adb_traffic", "tools/zeek", "diffs", "logs", "artifacts",
        ):
            self._ensure_dir(run_dir / sub)
        return RunContext(
            project_dir=project_dir,
            apk_path=apk_path,
            stage="stage2",
            run_id=run_id,
            run_dir=run_dir,
            started_at=now_utc_iso(),
        )
