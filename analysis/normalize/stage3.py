from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from analysis.runtime.context import RunContext


@dataclass
class EvidenceRef:
    tool: str
    path: str
    locator: str | None


@dataclass
class Indicator:
    id: str
    stage: str
    tool: str
    kind: str
    title: str
    value: str
    evidence: list[EvidenceRef]
    tags: list[str]


def _tool_evidence(ctx: RunContext, tool_name: str) -> list[EvidenceRef]:
    candidates = (
        ctx.run_dir / "tools" / tool_name / "tool_result.json",
        ctx.run_dir / "tools" / tool_name / "stdout.txt",
        ctx.run_dir / "tools" / tool_name / "stderr.txt",
    )
    for path in candidates:
        if path.exists():
            return [EvidenceRef(tool=tool_name, path=str(path.relative_to(ctx.run_dir)), locator=None)]
    return []


def _append_indicator(
    items: list[Indicator],
    tool_counts: dict[str, int],
    tool: str,
    kind: str,
    title: str,
    value: str,
    evidence: list[EvidenceRef],
    tags: list[str] | None = None,
) -> None:
    if not evidence:
        return
    indicator = Indicator(
        id=f"stage3:{tool}:{kind}:{len(items) + 1}",
        stage="stage3",
        tool=tool,
        kind=kind,
        title=title,
        value=value,
        evidence=evidence,
        tags=tags or [],
    )
    items.append(indicator)
    tool_counts[tool] = tool_counts.get(tool, 0) + 1


def normalize_stage3(ctx: RunContext, mobsf_result: Any | None, quark_result: Any | None) -> dict:
    items: list[Indicator] = []
    tool_counts: dict[str, int] = {}

    if mobsf_result is not None:
        static = getattr(mobsf_result, "static", None)
        if static is not None:
            evidence = _tool_evidence(ctx, "mobsf")
            for url in getattr(static, "urls_top", []) or []:
                _append_indicator(
                    items,
                    tool_counts,
                    "mobsf",
                    "url",
                    "Detected URL",
                    url,
                    evidence,
                )
            for domain in getattr(static, "domains_top", []) or []:
                _append_indicator(
                    items,
                    tool_counts,
                    "mobsf",
                    "host",
                    "Detected domain",
                    domain,
                    evidence,
                )
            for permission in getattr(static, "permissions_top", []) or []:
                _append_indicator(
                    items,
                    tool_counts,
                    "mobsf",
                    "permission",
                    "Detected permission",
                    permission,
                    evidence,
                )
            for component in getattr(static, "exported_top", []) or []:
                _append_indicator(
                    items,
                    tool_counts,
                    "mobsf",
                    "component",
                    "Detected exported component",
                    component,
                    evidence,
                )

    if quark_result is not None:
        summary = getattr(quark_result, "summary", None)
        matches = getattr(summary, "matches", None) if summary is not None else None
        if matches:
            base_evidence = _tool_evidence(ctx, "quark")
            for match in matches:
                evidence = list(base_evidence)
                output_path = getattr(match, "output_path", None)
                if output_path:
                    output_full = ctx.run_dir / output_path
                    if output_full.exists():
                        evidence.append(EvidenceRef(tool="quark", path=str(output_path), locator=None))
                value = getattr(match, "rule_name", None) or getattr(match, "rule_path", "")
                if not value:
                    continue
                _append_indicator(
                    items,
                    tool_counts,
                    "quark",
                    "quark_finding",
                    "Quark rule match",
                    value,
                    evidence,
                )

    apkid_payload = None
    apkid_source_path = None
    apkid_paths = (
        ctx.run_dir / "tools" / "apkid" / "raw" / "apkid.json",
        ctx.run_dir / "tools" / "apkid" / "stdout.txt",
    )
    for path in apkid_paths:
        if path.exists():
            try:
                apkid_payload = json.loads(path.read_text(encoding="utf-8"))
                apkid_source_path = path
            except (OSError, json.JSONDecodeError, ValueError):
                apkid_payload = None
            break
    if isinstance(apkid_payload, dict):
        files = apkid_payload.get("files") or apkid_payload.get("file") or []
        if isinstance(files, dict):
            files = [files]
        if isinstance(files, list):
            for file_entry in files:
                if not isinstance(file_entry, dict):
                    continue
                filename = file_entry.get("filename") or file_entry.get("file") or "-"
                matches = file_entry.get("matches") or {}
                if not isinstance(matches, dict):
                    continue
                for category, values in matches.items():
                    if values is None:
                        continue
                    if isinstance(values, str):
                        values_list = [values]
                    elif isinstance(values, list):
                        values_list = values
                    else:
                        values_list = [str(values)]
                    for value in values_list:
                        if value is None or value == "":
                            continue
                        evidence = []
                        if apkid_source_path and apkid_source_path.exists():
                            evidence.append(
                                EvidenceRef(
                                    tool="apkid",
                                    path=str(apkid_source_path.relative_to(ctx.run_dir)),
                                    locator=str(filename) if filename else None,
                                )
                            )
                        kind = "apkid_match"
                        if category == "yara_issue":
                            kind = "apkid_yara_issue"
                        _append_indicator(
                            items,
                            tool_counts,
                            "apkid",
                            kind,
                            "APKiD match",
                            f"{category}: {value}",
                            evidence,
                        )

    apkleaks_path = ctx.run_dir / "tools" / "apkleaks" / "raw" / "apkleaks.json"
    if apkleaks_path.exists():
        evidence = [
            EvidenceRef(
                tool="apkleaks",
                path=str(apkleaks_path.relative_to(ctx.run_dir)),
                locator=None,
            )
        ]
        _append_indicator(
            items,
            tool_counts,
            "apkleaks",
            "apkleaks_raw",
            "APKLeaks output",
            "apkleaks raw",
            evidence,
        )

    for tool_name in ("mobsf", "quark", "apkid", "apkleaks"):
        if tool_counts.get(tool_name, 0) == 0:
            evidence = _tool_evidence(ctx, tool_name)
            value = f"{tool_name} ok"
            _append_indicator(
                items,
                tool_counts,
                tool_name,
                "tool_execution",
                "Tool execution",
                value,
                evidence,
            )

    return {
        "schema": "tapka.indicators.v1",
        "stage": "stage3",
        "run_id": ctx.run_id,
        "items": [asdict(item) for item in items],
    }
