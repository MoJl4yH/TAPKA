from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from analysis.runtime.clock import now_utc_iso
from analysis.runtime.context import RunContext
from analysis.runtime.exec import run_command_capture
from analysis.runtime.fs import clear_tool_dir, write_tool_bundle
from analysis.settings import SETTINGS_DIR
from analysis.models.quark import QuarkReport, QuarkRuleResult, QuarkSummary


DEFAULT_RULES_DIR = SETTINGS_DIR / "quark-rules"
DEFAULT_SOURCE_RULES_DIR = Path.home() / ".quark-engine" / "quark-rules"
QUARK_COMMAND = "quark"


def _quark_is_matched(crime: dict) -> bool:
    """Module-level helper: a rule is considered matched if confidence >= 60% or score >= 1.0.

    score >= 1.0 means both APIs in a crime pair were found (full trace).
    BUG-41: raised score threshold from > 0 to >= 1.0 to reduce partial-match noise.
    """
    conf_str = crime.get("confidence", "0%")
    try:
        conf_val = int(conf_str.replace("%", ""))
    except (ValueError, AttributeError):
        conf_val = 0
    return conf_val >= 60 or crime.get("score", 0) >= 1.0


@dataclass
class QuarkConfig:
    rules_dir: Path | None = None
    timeout_sec: int = 600              # monolith timeout
    per_rule_timeout_sec: int = 60      # per-rule timeout in fallback mode
    max_rules: int | None = None        # debug mode: process first N rules


class QuarkRunner:
    def __init__(
        self,
        config: QuarkConfig | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> None:
        self.config = config or QuarkConfig()
        self.on_progress = on_progress

    def run(
        self,
        apk_path: Path,
        out_dir: Path,
        run_dir: Path,
        ctx: RunContext | None = None,
    ) -> QuarkReport:
        report = QuarkReport(status="skipped")

        if shutil.which(QUARK_COMMAND) is None:
            report.status = "missing"
            self._append_report_error(report, "quark executable not found in PATH.")
            return report

        if ctx is not None:
            clear_tool_dir(ctx, "quark")

        rules_dir = self._ensure_rules_dir()
        if not rules_dir:
            report.status = "missing_rules"
            self._append_report_error(report, "Quark rules directory not found.")
            return report

        rules_path = rules_dir / "rules"
        if not rules_path.is_dir():
            rules_path = rules_dir
        report.rules_dir = str(rules_path)
        out_dir.mkdir(parents=True, exist_ok=True)

        rule_files = sorted(rules_path.glob("*.json"))
        if not rule_files:
            report.status = "missing_rules"
            self._append_report_error(report, f"No *.json rules found in {rules_path}")
            return report
        if self.config.max_rules is not None:
            rule_files = rule_files[: self.config.max_rules]

        output_json_path = out_dir / "quark_output.json"
        tool_started_at = now_utc_iso() if ctx is not None else None

        # ── 1. Monolith run ──
        self._emit(f"Running Quark rules directory ({len(rule_files)} rules)...")
        monolith_cmd = [
            QUARK_COMMAND,
            "-r", str(rules_path),
            "-a", str(apk_path),
            "--output", str(output_json_path),
        ]
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        monolith_exit = 0
        monolith_stdout = ""
        monolith_stderr = ""
        timed_out = False

        try:
            monolith_exit, monolith_stdout, monolith_stderr = run_command_capture(
                monolith_cmd,
                env=env,
                timeout=self.config.timeout_sec,
                stderr_cb=self._emit,
                kill_process_group=True,
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            monolith_exit = 1
            monolith_stderr = f"Timeout after {self.config.timeout_sec}s"
            self._emit(f"Quark monolith timed out after {self.config.timeout_sec}s.")

        # Save monolith stdout/stderr to tool files.
        if ctx is not None:
            tool_root = ctx.run_dir / "tools" / "quark"
            tool_root.mkdir(parents=True, exist_ok=True)
            (tool_root / "stdout.txt").write_text(monolith_stdout, encoding="utf-8")
            (tool_root / "stderr.txt").write_text(monolith_stderr, encoding="utf-8")

        # ── 2. OOM detection ──
        is_oom = (
            not timed_out
            and (
                monolith_exit in (137, 9)
                or "Killed" in monolith_stderr
                or (monolith_exit != 0 and not output_json_path.exists())
            )
        )

        if is_oom:
            # ── 3. Per-rule fallback ──
            self._emit(
                f"Quark monolith killed (exit {monolith_exit}). "
                f"Switching to per-rule mode..."
            )
            # Mark the start of fallback section in stderr.txt.
            if ctx is not None:
                tool_root = ctx.run_dir / "tools" / "quark"
                with (tool_root / "stderr.txt").open("a", encoding="utf-8") as fh:
                    fh.write("\n\n=== PER-RULE FALLBACK ===\n")

            self._emit(f"Found {len(rule_files)} Quark rules. Starting per-rule analysis...")
            crimes, apk_meta, stats = self._run_per_rule(
                apk_path=apk_path,
                rule_files=rule_files,
                out_dir=out_dir,
            )
            tool_finished_at = now_utc_iso() if ctx is not None else None

            total_score = sum(c.get("score", 0) for c in crimes)
            combined = {
                "md5": apk_meta.get("md5", ""),
                "apk_filename": apk_meta.get("apk_filename", apk_path.name),
                "size_bytes": apk_meta.get("size_bytes", 0),
                "threat_level": self._compute_threat_level(total_score),
                "total_score": round(total_score, 4),
                "crimes": crimes,
            }
            output_json_path.write_text(
                json.dumps(combined, ensure_ascii=False, indent=2), encoding="utf-8"
            )

            if ctx is not None and output_json_path.exists():
                tool_output = ctx.run_dir / "tools" / "quark" / "quark_output.json"
                shutil.copy2(output_json_path, tool_output)

            successful = stats["total"] - stats["failed"] - stats["skipped"]
            if successful > 0:
                report.status = "ok"
                if stats["failed"] > 0:
                    self._append_report_error(
                        report,
                        f"Per-rule fallback: {stats['failed']} failed "
                        f"({stats['timed_out']} timeout, {stats['oom']} OOM)",
                    )
            else:
                report.status = "fail"
                self._append_report_error(report, "Per-rule fallback: all rules failed.")

            matches = [
                QuarkRuleResult(
                    rule_name=c.get("crime", ""),
                    rule_path=c.get("rule", ""),
                    matched=True,
                )
                for c in crimes
                if self._is_matched(c)
            ]
            report.summary = QuarkSummary(
                rules_total=stats["total"],
                rules_matched=len(matches),
                rules_failed=stats["failed"],
                rules_skipped=stats["skipped"],
                rules_timed_out=stats["timed_out"],
                matches=matches,
                artifacts={
                    "outputs_dir": self._relpath(run_dir, out_dir) + "/",
                    **(
                        {"output_json": self._relpath(run_dir, output_json_path)}
                        if output_json_path.exists()
                        else {}
                    ),
                },
            )

            if ctx is not None and tool_started_at and tool_finished_at:
                artifacts_dict: dict[str, str] = {}
                if out_dir.exists():
                    artifacts_dict["outputs_dir"] = self._relpath(ctx.run_dir, out_dir) + "/"
                if output_json_path.exists():
                    artifacts_dict["output_json"] = self._relpath(ctx.run_dir, output_json_path)
                per_rule_log = out_dir / "per_rule_log.jsonl"
                if per_rule_log.exists():
                    artifacts_dict["per_rule_log"] = self._relpath(ctx.run_dir, per_rule_log)
                primary_index = write_tool_bundle(
                    ctx,
                    "quark",
                    ["quark", "per-rule-fallback", f"{len(rule_files)}-rules"],
                    tool_started_at,
                    tool_finished_at,
                    monolith_exit,
                    monolith_stdout,
                    monolith_stderr,
                    artifacts_dict,
                )
                if primary_index:
                    tools_index = ctx.meta.setdefault("tools_index", [])
                    tools_index[:] = [
                        e for e in tools_index
                        if e.get("tool") not in ("quark", "quark_retry")
                    ]
                    tools_index.append(primary_index)

            return report

        # -- 4. Monolith: process result (success or regular error) --
        tool_finished_at = now_utc_iso() if ctx is not None else None

        if monolith_exit == 0 and output_json_path.exists():
            try:
                data = json.loads(output_json_path.read_text(encoding="utf-8"))
                crimes = data.get("crimes", [])
                report.status = "ok"
                matches = [
                    QuarkRuleResult(
                        rule_name=c.get("crime", ""),
                        rule_path=c.get("rule", ""),
                        matched=True,
                    )
                    for c in crimes
                    if self._is_matched(c)
                ]
                report.summary = QuarkSummary(
                    rules_total=len(rule_files),
                    rules_matched=len(matches),
                    rules_failed=0,
                    rules_skipped=0,
                    rules_timed_out=0,
                    matches=matches,
                    artifacts={
                        "outputs_dir": self._relpath(run_dir, out_dir) + "/",
                        "output_json": self._relpath(run_dir, output_json_path),
                    },
                )
            except (json.JSONDecodeError, OSError) as exc:
                report.status = "fail"
                self._append_report_error(report, f"Failed to parse monolith output: {exc}")
        elif timed_out:
            report.status = "fail"
            self._append_report_error(
                report, f"Quark monolith timed out after {self.config.timeout_sec}s."
            )
        else:
            report.status = "fail"
            self._append_report_error(
                report, f"Quark monolith failed (exit {monolith_exit})."
            )

        if ctx is not None and output_json_path.exists():
            tool_output = ctx.run_dir / "tools" / "quark" / "quark_output.json"
            shutil.copy2(output_json_path, tool_output)

        if ctx is not None and tool_started_at and tool_finished_at:
            artifacts_dict = {}
            if out_dir.exists():
                artifacts_dict["outputs_dir"] = self._relpath(ctx.run_dir, out_dir) + "/"
            if output_json_path.exists():
                artifacts_dict["output_json"] = self._relpath(ctx.run_dir, output_json_path)
            primary_index = write_tool_bundle(
                ctx,
                "quark",
                ["quark", "monolith", f"{len(rule_files)}-rules"],
                tool_started_at,
                tool_finished_at,
                monolith_exit,
                monolith_stdout,
                monolith_stderr,
                artifacts_dict,
            )
            if primary_index:
                tools_index = ctx.meta.setdefault("tools_index", [])
                tools_index[:] = [e for e in tools_index if e.get("tool") != "quark"]
                tools_index.append(primary_index)

        return report

    def _run_per_rule(
        self,
        apk_path: Path,
        rule_files: list[Path],
        out_dir: Path,
    ) -> tuple[list[dict], dict, dict]:
        """
        Run each rule in a separate subprocess.
        Each process: quark -r <rule.json> -a <apk> --output <tmp.json>
        OS memory is reclaimed after each process exits.

        Returns:
            crimes:   list[dict] - collected crime entries
            apk_meta: dict       - md5, apk_filename, size_bytes (from first successful run)
            stats:    dict       - total, matched, failed, skipped, timed_out, oom
        """
        crimes: list[dict] = []
        apk_meta: dict = {}
        stats = {
            "total": len(rule_files),
            "matched": 0,
            "failed": 0,
            "skipped": 0,
            "timed_out": 0,
            "oom": 0,
        }

        per_rule_timeout = self.config.per_rule_timeout_sec
        tmp_dir = out_dir / "_per_rule_tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)

        log_path = out_dir / "per_rule_log.jsonl"
        log_handle = log_path.open("w", encoding="utf-8")

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        MAX_CONSECUTIVE_FAILURES = 10
        consecutive_failures = 0

        for idx, rule_path in enumerate(rule_files):
            rule_name = rule_path.stem
            progress_pct = int((idx / len(rule_files)) * 100)

            self._emit(f"QUARK_RULE:{idx + 1}/{len(rule_files)}:{rule_name}")
            self._emit(f"{progress_pct}%")

            rule_output = tmp_dir / f"{rule_name}.json"
            cmd = [
                QUARK_COMMAND,
                "-r", str(rule_path),
                "-a", str(apk_path),
                "--output", str(rule_output),
            ]

            entry: dict = {
                "rule": rule_name,
                "rule_file": rule_path.name,
                "status": "pending",
                "exit_code": None,
                "duration_sec": None,
                "error": None,
                "oom_detected": False,
            }

            try:
                start = time.monotonic()
                exit_code, _stdout, stderr = run_command_capture(
                    cmd,
                    env=env,
                    timeout=per_rule_timeout,
                    kill_process_group=True,
                )
                entry["duration_sec"] = round(time.monotonic() - start, 2)
                entry["exit_code"] = exit_code

                # OOM detection (exit 137 = SIGKILL, or "Killed" in stderr)
                is_oom = exit_code in (137, 9) or "Killed" in (stderr or "")
                entry["oom_detected"] = is_oom

                if is_oom:
                    entry["status"] = "oom"
                    entry["error"] = f"OOM-like termination (exit {exit_code})"
                    stats["oom"] += 1
                    stats["failed"] += 1
                    consecutive_failures += 1
                    self._emit(f"  Rule {rule_name}: OOM (exit {exit_code})")

                elif exit_code == 0 and rule_output.exists():
                    try:
                        data = json.loads(rule_output.read_text(encoding="utf-8"))
                        rule_crimes = data.get("crimes", [])

                        if not apk_meta:
                            apk_meta = {
                                k: data.get(k, "")
                                for k in ("md5", "apk_filename", "size_bytes")
                            }

                        crimes.extend(rule_crimes)
                        entry["status"] = "ok"
                        consecutive_failures = 0

                    except (json.JSONDecodeError, OSError) as exc:
                        entry["status"] = "parse_error"
                        entry["error"] = str(exc)[:200]
                        stats["failed"] += 1
                        consecutive_failures += 1

                elif exit_code != 0:
                    entry["status"] = "error"
                    entry["error"] = (stderr or "").strip()[:200]
                    stats["failed"] += 1
                    consecutive_failures += 1

                else:
                    # exit 0, but no output file
                    entry["status"] = "no_output"
                    stats["skipped"] += 1
                    consecutive_failures += 1

            except subprocess.TimeoutExpired:
                entry["status"] = "timeout"
                entry["duration_sec"] = per_rule_timeout
                stats["timed_out"] += 1
                stats["failed"] += 1
                consecutive_failures += 1
                self._emit(f"  Rule {rule_name}: timeout ({per_rule_timeout}s)")

            except Exception as exc:  # pylint: disable=broad-exception-caught
                entry["status"] = "exception"
                entry["error"] = str(exc)[:200]
                stats["failed"] += 1
                consecutive_failures += 1

            finally:
                log_handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
                log_handle.flush()
                # Delete tmp output immediately to save disk space.
                if rule_output.exists():
                    try:
                        rule_output.unlink()
                    except OSError:
                        pass

            # Early exit on cascading failures.
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                remaining = len(rule_files) - idx - 1
                self._emit(
                    f"Aborting: {MAX_CONSECUTIVE_FAILURES} consecutive failures. "
                    f"Skipping remaining {remaining} rules."
                )
                stats["skipped"] += remaining
                break

        log_handle.close()
        shutil.rmtree(tmp_dir, ignore_errors=True)

        # Count matched entries.
        for c in crimes:
            if self._is_matched(c):
                stats["matched"] += 1

        self._emit("100%")
        self._emit(
            f"Quark done: {stats['matched']} matched, "
            f"{stats['failed']} failed ({stats['timed_out']} timeout, {stats['oom']} OOM), "
            f"{stats['total']} total"
        )
        return crimes, apk_meta, stats

    @staticmethod
    def _is_matched(crime: dict) -> bool:
        """A rule is considered matched if confidence >= 60% or score > 0."""
        return _quark_is_matched(crime)

    @staticmethod
    def _compute_threat_level(total_score: float) -> str:
        """Reproduce Quark threat_level logic."""
        if total_score >= 80:
            return "High Risk"
        if total_score >= 40:
            return "Moderate Risk"
        if total_score >= 1:
            return "Low Risk"
        return "Safe"

    def _ensure_rules_dir(self) -> Path | None:
        target = self.config.rules_dir or DEFAULT_RULES_DIR
        if target.exists():
            return target
        if DEFAULT_SOURCE_RULES_DIR.exists():
            SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
            shutil.move(str(DEFAULT_SOURCE_RULES_DIR), str(target))
            return target
        return None

    def _emit(self, message: str) -> None:
        if self.on_progress:
            self.on_progress(message)

    def _relpath(self, run_dir: Path, path: Path) -> str:
        try:
            return str(path.relative_to(run_dir))
        except ValueError:
            return str(path)

    def _append_report_error(self, report: QuarkReport, message: str) -> None:
        errors = report.errors if isinstance(report.errors, list) else []
        errors = [str(item) for item in errors]
        errors.append(message)
        report.errors = errors
