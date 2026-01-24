from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from analysis.runtime.clock import now_utc_iso


@dataclass
class RunContext:
    project_dir: Path
    apk_path: Path
    stage: str
    run_id: str
    run_dir: Path
    started_at: str
    meta: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, project_dir: Path, apk_path: Path, stage: str) -> "RunContext":
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        run_id = f"{timestamp}_{uuid4().hex[:6]}"
        started_at = now_utc_iso()
        run_dir = project_dir / "runs" / f"{run_id}_{stage}"
        return cls(
            project_dir=project_dir,
            apk_path=apk_path,
            stage=stage,
            run_id=run_id,
            run_dir=run_dir,
            started_at=started_at,
        )

    @classmethod
    def from_run_dir(
        cls,
        project_dir: Path,
        apk_path: Path,
        stage: str,
        run_dir: Path,
    ) -> "RunContext":
        run_id = run_dir.name
        started_at = now_utc_iso()
        meta: dict[str, Any] = {}
        run_path = run_dir / "run.json"
        if run_path.exists():
            try:
                data = json.loads(run_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError, ValueError):
                data = {}
            if data.get("schema") == "tapka.run.v1":
                run_id = data.get("run_id") or run_id
                started_at = data.get("started_at") or started_at
                tools = data.get("tools")
                if isinstance(tools, list):
                    meta["tools_index"] = list(tools)
            else:
                started_at = data.get("started_at") or started_at
        return cls(
            project_dir=project_dir,
            apk_path=apk_path,
            stage=stage,
            run_id=run_id,
            run_dir=run_dir,
            started_at=started_at,
            meta=meta,
        )
