from __future__ import annotations

import base64
import html
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from analysis.severity import SeverityEngine
from analysis.stages import STAGE_CROSS_TOOL, STAGE_DYNAMIC, STAGE_OVERALL, STAGE_STATIC
from analysis.storage import Storage
from models import (
    BaseReportModel,
    Finding,
    OverallReportModel,
    Project,
    Run,
    ProjectInfo,
    RunInfo,
    Stage1ReportModel,
    Stage2ReportModel,
    Stage3ReportModel,
    ToolStatus,
)

REPORT_FILENAMES = {
    STAGE_STATIC: ("stage1_report.json", "stage1_report.html"),
    STAGE_DYNAMIC: ("stage2_report.json", "stage2_report.html"),
    STAGE_CROSS_TOOL: ("stage3_report.json", "stage3_report.html"),
    STAGE_OVERALL: ("overall_report.json", "overall_report.html"),
}

SEVERITY_ORDER = ["high", "medium", "low", "info"]
APP_NAME = "TAPKA"
APP_TAGLINE = "Tools for APK analysis"
APP_DESCRIPTION = (
    "TAPKA helps triage Android APKs with static analysis pipelines, "
    "collecting findings, artifacts, and reports for investigation."
)

CATEGORY_DESCRIPTIONS = {
    "ndv_remote_command": "Remote command channels may enable remote tasking or payload control.",
    "ndv_traffic_intercept_vpn": "VPN/TUN indicators may allow traffic interception or monitoring.",
    "ndv_screen_capture_mediaprojection": "MediaProjection usage can capture screens or frames.",
    "ndv_accessibility_surveillance": "Accessibility APIs can observe UI content and actions.",
    "ndv_keylogging_like": "Accessibility text events can resemble keylogging behavior.",
    "ndv_mic_eavesdropping": "Audio APIs with RECORD_AUDIO suggest microphone access.",
    "ndv_camera_surveillance": "Camera APIs combined with permissions indicate camera use.",
    "ndv_geo_tracking_background": "Background location tracking can occur persistently.",
    "ndv_geo_tracking_foreground": "Foreground location access can track user position.",
    "ndv_clipboard_monitoring": "Clipboard APIs can capture copied data.",
    "ndv_sms_intercept": "SMS permissions may allow message interception.",
    "ndv_notification_listener": "Notification listener access can read user notifications.",
    "ndv_overlay_abuse": "Overlay capabilities can be abused for UI phishing.",
    "sec_tls_trust_all": "Trust-all TLS patterns weaken transport security.",
    "sec_hostname_verifier_bypass": "Hostname verification bypass enables MITM risks.",
    "sec_cleartext_traffic_allowed": "Cleartext traffic allowance weakens transport security.",
    "sec_insecure_webview_bridge": "WebView JS bridges increase attack surface.",
    "sec_insecure_webview_file_access": "WebView file access can expose local files.",
    "sec_custom_ca_store_or_user_certs": "Custom trust store usage can weaken TLS validation.",
    "sec_proxy_setting_modification": "Proxy settings manipulation can redirect traffic.",
    "vul_exported_component_no_permission": "Exported components without permissions are risky.",
    "vul_exported_provider_risky": "Exported providers can leak or expose data.",
    "vul_fileprovider_misconfig": "FileProvider misconfigurations can expose files.",
    "vul_pendingintent_mutable": "Mutable PendingIntent can be hijacked by other apps.",
    "vul_deeplink_intent_injection": "Deeplink intents may allow external input injection.",
    "vul_backup_enabled": "Backups can expose app data if not hardened.",
    "vul_debuggable_true": "Debuggable builds are high risk in production.",
    "ndv_dynamic_code_loading": "Dynamic code loading enables runtime payloads.",
    "ndv_native_code_loader_suspicious": "Native code loading may hide functionality.",
    "ndv_reflection_heavy": "Heavy reflection suggests obfuscation or dynamic behavior.",
    "ndv_download_execute": "Download then execute patterns are high risk.",
    "secret_private_key_pem": "Embedded private keys allow credential compromise.",
    "secret_hardcoded_token_or_apikey": "Hardcoded tokens or API keys expose secrets.",
    "secret_jwt_embedded": "Embedded JWTs can leak authentication data.",
    "secret_password_like": "Password-like strings indicate hardcoded credentials.",
    "secret_endpoints_hardcoded": "Hardcoded endpoints expose backend infrastructure.",
    "indicator_endpoints_hardcoded": "Extracted URLs/IPs indicate external endpoints (noise possible).",
    "persist_boot_completed": "Boot receivers indicate persistence mechanisms.",
    "persist_workmanager_periodic": "Periodic WorkManager tasks indicate persistence.",
    "persist_jobscheduler_periodic": "JobScheduler periodic tasks indicate persistence.",
    "persist_alarmmanager_repeating": "Repeating alarms indicate persistence.",
    "anomaly_root_detection": "Root checks suggest anti-analysis behavior.",
    "anomaly_frida_xposed_magisk_detection": "Frida/Xposed detection indicates anti-tampering.",
    "anomaly_emulator_detection": "Emulator checks indicate evasion tactics.",
    "anomaly_obfuscation_heavy": "Heavy obfuscation can conceal intent.",
    "anomaly_anti_debug": "Anti-debugging logic can hinder analysis.",
    "supplychain_signature_invalid": "Signature verification failed.",
    "supplychain_signature_scheme_v1_only": "v1-only signing is weaker on newer Android.",
    "supplychain_debug_certificate": "Debug certificates should not be in production builds.",
    "supplychain_cert_expired": "Expired certificates indicate signing issues.",
}

ENDPOINT_DENYLIST = {
    "schemas.android.com",
    "developer.android.com",
    "www.w3.org",
    "www.ietf.org",
    "docs.python.org",
    "semver.org",
    "learn.microsoft.com",
    "github.com",
}

ENDPOINT_TOP_N = 100
ENDPOINT_EXAMPLE_LIMIT = 3


def _logo_data_uri() -> str | None:
    logo_path = Path(__file__).resolve().parent.parent / "ui" / "87288873-75ab-4871-bf62-f126ff451e6c.png"
    if not logo_path.exists():
        return None
    data = base64.b64encode(logo_path.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{data}"


def _endpoint_kind(finding: Finding) -> str | None:
    sources = finding.sources or []
    if any(source.startswith("rg:endpoint_url") for source in sources):
        return "url"
    if any(source.startswith("rg:endpoint_ipv4") for source in sources):
        return "ip"
    return None


def _endpoint_value(finding: Finding) -> str | None:
    value = (finding.evidence or finding.match or "").strip()
    return value or None


def _endpoint_source_label(finding: Finding) -> str | None:
    for source in finding.sources or []:
        if source.startswith("rg:endpoint_"):
            return source
    if finding.sources:
        return finding.sources[0]
    return None


def _endpoint_example(finding: Finding) -> dict | None:
    path = finding.file_path or finding.location
    if not path:
        return None
    return {
        "path": path,
        "line": finding.line,
        "source": _endpoint_source_label(finding),
    }


def _is_noise_url(value: str) -> bool:
    try:
        host = urlparse(value).hostname or ""
    except ValueError:
        host = ""
    if not host:
        return False
    return host.lower() in ENDPOINT_DENYLIST


def _collect_endpoints(
    findings: list[Finding],
) -> tuple[dict[str, dict], dict[str, dict]]:
    url_map: dict[str, dict] = {}
    ip_map: dict[str, dict] = {}
    for finding in findings:
        kind = _endpoint_kind(finding)
        if not kind:
            continue
        value = _endpoint_value(finding)
        if not value:
            continue
        target = url_map if kind == "url" else ip_map
        entry = target.get(value)
        if entry is None:
            entry = {"value": value, "examples": [], "noise": False}
            if kind == "url":
                entry["noise"] = _is_noise_url(value)
            target[value] = entry
        example = _endpoint_example(finding)
        if example and example not in entry["examples"]:
            if len(entry["examples"]) < ENDPOINT_EXAMPLE_LIMIT:
                entry["examples"].append(example)
    return url_map, ip_map


def _format_example_location(example: dict | None) -> str:
    if not example:
        return "-"
    path = example.get("path") or "-"
    line = example.get("line")
    if line:
        return f"{path}:{line}"
    return path


class ReportManager:
    def __init__(self, storage: Storage):
        self.storage = storage

    def report_paths(self, run_dir: Path, stage: str) -> tuple[Path, Path]:
        json_name, html_name = REPORT_FILENAMES[stage]
        artifacts_dir = run_dir / "artifacts"
        return artifacts_dir / json_name, artifacts_dir / html_name

    def generate_stage1(self, run: Run, run_dir: Path, findings: list[Finding]) -> tuple[Path, Path]:
        project = self.storage.load_project(run.project_id)
        self._write_endpoint_artifacts(run_dir, findings)
        report = self._build_stage1_report(project, run, run_dir, findings)
        json_path, html_path = self.report_paths(run_dir, STAGE_STATIC)
        json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        html_path.write_text(Stage1HtmlRenderer().render(report), encoding="utf-8")
        return json_path, html_path

    def generate_stage2_stub(self, run: Run, run_dir: Path) -> tuple[Path, Path]:
        report = self._build_stub_report(Stage2ReportModel, run, run_dir, "Dynamic analysis")
        return self._write_stub(report, run_dir, STAGE_DYNAMIC, "Dynamic analysis")

    def generate_stage3_stub(self, run: Run, run_dir: Path) -> tuple[Path, Path]:
        report = self._build_stub_report(
            Stage3ReportModel,
            run,
            run_dir,
            "Cross-tool analysis",
        )
        return self._write_stub(report, run_dir, STAGE_CROSS_TOOL, "Cross-tool analysis")

    def generate_overall_stub(self, run: Run, run_dir: Path) -> tuple[Path, Path]:
        report = self._build_stub_report(OverallReportModel, run, run_dir, "Overall report")
        return self._write_stub(report, run_dir, STAGE_OVERALL, "Overall report")

    def regenerate_stage1_from_json(self, run_dir: Path) -> Path | None:
        json_path, html_path = self.report_paths(run_dir, STAGE_STATIC)
        if not json_path.exists():
            return None
        report = Stage1ReportModel.model_validate_json(json_path.read_text(encoding="utf-8"))
        self._write_endpoint_artifacts(run_dir, report.findings)
        report.artifacts = self._collect_artifacts(run_dir)
        html_path.write_text(Stage1HtmlRenderer().render(report), encoding="utf-8")
        return html_path

    def ensure_stub_reports(self, run: Run, run_dir: Path) -> None:
        for stage, generator in (
            (STAGE_DYNAMIC, self.generate_stage2_stub),
            (STAGE_CROSS_TOOL, self.generate_stage3_stub),
            (STAGE_OVERALL, self.generate_overall_stub),
        ):
            json_path, html_path = self.report_paths(run_dir, stage)
            if json_path.exists() and html_path.exists():
                continue
            generator(run, run_dir)

    def _write_endpoint_artifacts(self, run_dir: Path, findings: list[Finding]) -> None:
        artifacts_dir = run_dir / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        url_map, ip_map = _collect_endpoints(findings)

        urls = sorted(url_map)
        ips = sorted(ip_map)
        urls_txt = artifacts_dir / "endpoints.urls.txt"
        ips_txt = artifacts_dir / "endpoints.ips.txt"
        urls_json = artifacts_dir / "endpoints.urls.json"
        ips_json = artifacts_dir / "endpoints.ips.json"

        urls_txt.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")
        ips_txt.write_text("\n".join(ips) + ("\n" if ips else ""), encoding="utf-8")

        urls_payload = [url_map[value] for value in urls]
        ips_payload = [ip_map[value] for value in ips]
        urls_json.write_text(json.dumps(urls_payload, indent=2), encoding="utf-8")
        ips_json.write_text(json.dumps(ips_payload, indent=2), encoding="utf-8")

    def load_findings(self, run: Run, run_dir: Path) -> list[Finding]:
        findings_path = run_dir / "findings" / "findings.json"
        if run.findings_path:
            findings_path = Path(run.findings_path)
        if not findings_path.exists():
            return []
        payload = json.loads(findings_path.read_text(encoding="utf-8"))
        findings = [Finding.model_validate(item) for item in payload]
        SeverityEngine.apply(findings)
        return findings

    def _build_stage1_report(
        self, project: Project, run: Run, run_dir: Path, findings: list[Finding]
    ) -> Stage1ReportModel:
        now = datetime.now().isoformat(timespec="seconds")
        apk_path = self.storage.get_apk_path(project.project_id)
        package_info = self._parse_package_info(run_dir)

        project_info = project.apk_meta
        project_model = ProjectInfo(
            project_id=project.project_id,
            apk_name=project_info.name if project_info else None,
            apk_sha256=project_info.sha256 if project_info else None,
            apk_size=project_info.size if project_info else None,
            apk_path=str(apk_path) if apk_path else None,
            package_name=package_info.get("package_name"),
            version_name=package_info.get("version_name"),
            version_code=package_info.get("version_code"),
        )

        duration_sec = None
        if run.finished_at:
            try:
                duration_sec = (
                    datetime.fromisoformat(run.finished_at) - datetime.fromisoformat(run.started_at)
                ).total_seconds()
            except (ValueError, TypeError):
                duration_sec = None
        run_model = RunInfo(
            run_id=run.run_id,
            stage=run.stage,
            status=run.status,
            started_at=run.started_at,
            finished_at=run.finished_at,
            duration_sec=duration_sec,
            run_dir=str(run_dir),
        )

        tool_statuses = self._build_tool_statuses(run, run_dir, findings)
        manifest_summary = self._manifest_summary(run_dir)
        endpoints_summary = self._endpoint_summary(findings)
        signing_summary = self._signing_summary(findings)
        artifacts = self._collect_artifacts(run_dir)

        return Stage1ReportModel(
            report_type=STAGE_STATIC,
            generated_at=now,
            project=project_model,
            run=run_model,
            tool_statuses=tool_statuses,
            findings=findings,
            artifacts=artifacts,
            manifest_permissions=manifest_summary["permissions"],
            manifest_exported=manifest_summary["exported"],
            manifest_flags=manifest_summary["flags"],
            endpoints_summary=endpoints_summary,
            signing_summary=signing_summary,
        )

    def _build_stub_report(
        self,
        model_cls,
        run: Run,
        run_dir: Path,
        label: str,
        stage: str | None = None,
    ) -> BaseReportModel:
        stage_id = stage or run.stage
        now = datetime.now().isoformat(timespec="seconds")
        project = self.storage.load_project(run.project_id)
        apk_path = self.storage.get_apk_path(project.project_id)
        project_info = project.apk_meta
        project_model = ProjectInfo(
            project_id=project.project_id,
            apk_name=project_info.name if project_info else None,
            apk_sha256=project_info.sha256 if project_info else None,
            apk_size=project_info.size if project_info else None,
            apk_path=str(apk_path) if apk_path else None,
        )
        run_model = RunInfo(
            run_id=run.run_id,
            stage=stage_id,
            status=run.status,
            started_at=run.started_at,
            finished_at=run.finished_at,
            run_dir=str(run_dir),
        )
        notes = [
            "Not implemented yet.",
            "This report will be extended in future updates.",
        ]
        return model_cls(
            report_type=stage_id,
            generated_at=now,
            project=project_model,
            run=run_model,
            tool_statuses=[],
            findings=[],
            artifacts=self._collect_artifacts(run_dir),
            status="not_implemented",
            notes=notes,
        )

    def _write_stub(
        self, report: BaseReportModel, run_dir: Path, stage: str, label: str
    ) -> tuple[Path, Path]:
        json_path, html_path = self.report_paths(run_dir, stage)
        json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        html_path.write_text(StubHtmlRenderer().render(report, label, stage), encoding="utf-8")
        return json_path, html_path

    def _build_tool_statuses(
        self, run: Run, run_dir: Path, findings: list[Finding]
    ) -> list[ToolStatus]:
        statuses: dict[str, list[str]] = {}
        for result in run.command_results:
            statuses.setdefault(result.tool, []).append(result.status or "unknown")

        def pick_status(tool: str) -> str:
            values = statuses.get(tool, [])
            if not values:
                return "not_implemented"
            if "fail" in values:
                return "fail"
            if "partial" in values:
                return "partial"
            if "success" in values:
                return "ok"
            return "ok"

        jadx_errors = self._parse_jadx_errors(run_dir)
        apktool_reason = self._stderr_reason(run_dir / "logs" / "apktool.stderr.txt")
        yara_matches, yara_rules = self._parse_yara_matches(run_dir)
        rg_url, rg_ip = self._count_rg_endpoints(findings)
        signing_findings = sum(
            1 for finding in findings if finding.category.startswith("supplychain_")
        )
        signing_status = pick_status("apksigner")
        keytool_status = pick_status("keytool")
        if keytool_status == "fail":
            signing_status = "fail"
        elif keytool_status == "partial" and signing_status == "ok":
            signing_status = "partial"
        if signing_findings:
            signing_status = "partial" if signing_status == "ok" else signing_status

        tool_statuses = [
            ToolStatus(
                tool="jadx",
                status=pick_status("jadx"),
                error_count=jadx_errors,
                details=f"errors: {jadx_errors}" if jadx_errors is not None else None,
            ),
            ToolStatus(
                tool="apktool",
                status=pick_status("apktool"),
                details=apktool_reason,
            ),
            ToolStatus(
                tool="yara",
                status=pick_status("yara"),
                matches=yara_matches,
                rules=yara_rules,
                details=(
                    f"matches: {yara_matches}, rules: {yara_rules}"
                    if yara_matches is not None
                    else None
                ),
            ),
            ToolStatus(
                tool="rg",
                status=pick_status("rg"),
                details=f"urls: {rg_url}, ips: {rg_ip}",
            ),
            ToolStatus(
                tool="signing",
                status=signing_status,
                details=f"supplychain findings: {signing_findings}",
            ),
        ]
        return tool_statuses

    def _stderr_reason(self, path: Path) -> str | None:
        if not path.exists():
            return None
        content = path.read_text(encoding="utf-8", errors="replace").strip()
        return content.splitlines()[0] if content else None

    def _parse_jadx_errors(self, run_dir: Path) -> int | None:
        for suffix in ("stdout.txt", "stderr.txt"):
            path = run_dir / "logs" / f"jadx.{suffix}"
            if not path.exists():
                continue
            match = re.search(r"errors, count:\s*(\d+)", path.read_text(encoding="utf-8", errors="replace"))
            if match:
                return int(match.group(1))
        return None

    def _parse_yara_matches(self, run_dir: Path) -> tuple[int | None, int | None]:
        stdout_path = run_dir / "logs" / "yara.stdout.txt"
        if not stdout_path.exists():
            return None, None
        lines = [line for line in stdout_path.read_text(encoding="utf-8", errors="replace").splitlines() if line]
        rules = {line.split()[0] for line in lines if line.split()}
        return len(lines), len(rules)

    def _count_rg_endpoints(self, findings: list[Finding]) -> tuple[int, int]:
        url_map, ip_map = _collect_endpoints(findings)
        return len(url_map), len(ip_map)

    def _manifest_summary(self, run_dir: Path) -> dict[str, list[str]]:
        manifest_path = run_dir / "artifacts" / "out_apktool" / "AndroidManifest.xml"
        if not manifest_path.exists():
            return {"permissions": [], "exported": [], "flags": []}
        flags = []
        permissions = []
        exported = []
        try:
            ns = "{http://schemas.android.com/apk/res/android}"
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            for perm in root.findall("uses-permission") + root.findall("uses-permission-sdk-23"):
                name = perm.get(f"{ns}name") or perm.get("name")
                if name:
                    permissions.append(name)
            application = root.find("application")
            if application is not None:
                if (application.get(f"{ns}debuggable") or "false").lower() == "true":
                    flags.append("debuggable=true")
                if (application.get(f"{ns}allowBackup") or "false").lower() == "true":
                    flags.append("allowBackup=true")
                if (application.get(f"{ns}usesCleartextTraffic") or "false").lower() == "true":
                    flags.append("usesCleartextTraffic=true")
                fst = application.get(f"{ns}foregroundServiceType")
                if fst:
                    flags.append(f"foregroundServiceType={fst}")
                for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
                    for component in application.findall(tag):
                        exported_attr = component.get(f"{ns}exported")
                        if exported_attr is None:
                            has_intent = component.find("intent-filter") is not None
                            is_exported = has_intent and tag in ("activity", "activity-alias", "service", "receiver")
                        else:
                            is_exported = exported_attr.lower() == "true"
                        if is_exported:
                            name = component.get(f"{ns}name") or component.get("name") or "unknown"
                            exported.append(f"{tag}:{name}")
        except (ET.ParseError, OSError, ValueError):
            return {"permissions": [], "exported": [], "flags": []}
        return {
            "permissions": sorted(set(permissions)),
            "exported": sorted(set(exported)),
            "flags": sorted(set(flags)),
        }

    def _endpoint_summary(self, findings: list[Finding]) -> dict[str, int]:
        url_count, ip_count = self._count_rg_endpoints(findings)
        return {"urls": url_count, "ips": ip_count}

    def _signing_summary(self, findings: list[Finding]) -> dict[str, int]:
        summary: dict[str, int] = {}
        for finding in findings:
            if not finding.category.startswith("supplychain_"):
                continue
            summary[finding.category] = summary.get(finding.category, 0) + 1
        return summary

    def _collect_artifacts(self, run_dir: Path) -> list[str]:
        paths: list[str] = []
        for path in sorted((run_dir / "logs").glob("*.txt")):
            paths.append(str(path.relative_to(run_dir)))
        artifacts_dir = run_dir / "artifacts"
        for path in sorted(artifacts_dir.glob("*")):
            if path.is_file():
                paths.append(str(path.relative_to(run_dir)))
        for json_name, html_name in REPORT_FILENAMES.values():
            for name in (json_name, html_name):
                report_path = artifacts_dir / name
                if report_path.exists():
                    rel = str(report_path.relative_to(run_dir))
                    if rel not in paths:
                        paths.append(rel)
        manifest_path = artifacts_dir / "out_apktool" / "AndroidManifest.xml"
        if manifest_path.exists():
            paths.append(str(manifest_path.relative_to(run_dir)))
        for folder in ("out_apktool", "out_jadx", "certs"):
            folder_path = artifacts_dir / folder
            if folder_path.exists():
                paths.append(str(folder_path.relative_to(run_dir)) + "/")
        return paths

    def _parse_package_info(self, run_dir: Path) -> dict[str, str]:
        stdout_path = run_dir / "logs" / "aapt2.stdout.txt"
        if not stdout_path.exists():
            return {}
        text = stdout_path.read_text(encoding="utf-8", errors="replace")
        match = re.search(
            r"package: name='([^']+)'\s+versionCode='([^']*)'\s+versionName='([^']*)'",
            text,
        )
        if not match:
            return {}
        return {
            "package_name": match.group(1),
            "version_code": match.group(2),
            "version_name": match.group(3),
        }


class Stage1HtmlRenderer:
    def render(self, report: Stage1ReportModel) -> str:
        context = self._build_context(report)

        return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>TAPKA Stage1 Report</title>
  <style>
    body {{
      margin: 0;
      font-family: "IBM Plex Sans", "Noto Sans", sans-serif;
      background: #121417;
      color: #e6e9ee;
    }}
    .container {{
      padding: 24px;
    }}
    .report-brand {{
      display: flex;
      gap: 16px;
      align-items: center;
      margin-bottom: 18px;
      padding-bottom: 12px;
      border-bottom: 1px solid #2b3138;
    }}
    .brand-logo {{
      width: 56px;
      height: 56px;
      border-radius: 12px;
      object-fit: contain;
      background: #1b1f24;
      border: 1px solid #2b3138;
      padding: 6px;
    }}
    .brand-name {{
      font-size: 22px;
      font-weight: 700;
      letter-spacing: 0.2px;
    }}
    .brand-tagline {{
      font-size: 13px;
      color: #9aa3ad;
      text-transform: uppercase;
      letter-spacing: 0.12em;
    }}
    .brand-desc {{
      margin: 6px 0 0 0;
    }}
    h1, h2, h3, h4 {{
      margin: 0 0 12px 0;
    }}
    .muted {{
      color: #9aa3ad;
    }}
    .grid {{
      display: grid;
      gap: 16px;
    }}
    .grid-3 {{
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    }}
    .card {{
      background: #1b1f24;
      border: 1px solid #2b3138;
      border-radius: 12px;
      padding: 16px;
    }}
    .summary-line {{
      display: grid;
      grid-template-columns: 140px minmax(0, 1fr);
      gap: 12px;
      margin-bottom: 6px;
    }}
    .summary-label {{
      color: #9aa3ad;
    }}
    .summary-value {{
      display: flex;
      gap: 8px;
      align-items: flex-start;
      min-width: 0;
    }}
    .summary-text {{
      min-width: 0;
      overflow-wrap: anywhere;
      word-break: break-word;
    }}
    .mono {{
      font-family: "IBM Plex Mono", "Menlo", monospace;
    }}
    .badge {{
      padding: 4px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
    }}
    .badge-high {{ background: #522; color: #ff9b9b; }}
    .badge-medium {{ background: #4a3926; color: #f5a65b; }}
    .badge-low {{ background: #293540; color: #8bb6ff; }}
    .badge-info {{ background: #1f2a2d; color: #4db7b0; }}
    .tool-card {{
      display: flex;
      flex-direction: column;
      gap: 6px;
    }}
    .tool-status {{
      font-weight: 600;
      text-transform: uppercase;
    }}
    .status-ok {{ color: #4db7b0; }}
    .status-partial {{ color: #f5a65b; }}
    .status-fail {{ color: #ff7b7b; }}
    .status-not_implemented {{ color: #9aa3ad; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 8px;
      table-layout: fixed;
    }}
    th, td {{
      text-align: left;
      padding: 8px;
      border-bottom: 1px solid #2b3138;
      vertical-align: top;
      min-width: 0;
    }}
    th {{
      font-size: 12px;
      text-transform: uppercase;
      color: #9aa3ad;
    }}
    .cell-pre {{
      margin: 0;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
      max-height: 140px;
      overflow: auto;
    }}
    .filters {{
      display: flex;
      gap: 12px;
      margin: 12px 0;
      flex-wrap: wrap;
      align-items: center;
    }}
    input, select {{
      background: #1b1f24;
      border: 1px solid #2b3138;
      border-radius: 8px;
      padding: 6px 10px;
      color: #e6e9ee;
    }}
    .endpoint-controls {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
      margin-bottom: 8px;
    }}
    .artifact-row {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 6px 0;
      border-bottom: 1px dashed #2b3138;
      gap: 12px;
    }}
    .artifact-path {{
      min-width: 0;
      overflow-wrap: anywhere;
      word-break: break-word;
    }}
    .copy-btn {{
      background: #1b1f24;
      border: 1px solid #2b3138;
      border-radius: 8px;
      padding: 4px 10px;
      color: #e6e9ee;
      cursor: pointer;
    }}
    .ghost-btn {{
      background: transparent;
      border: 1px dashed #2b3138;
      border-radius: 8px;
      padding: 4px 10px;
      color: #e6e9ee;
      cursor: pointer;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="report-brand">
      {context["brand_logo"]}
      <div>
        <div class="brand-name">{html.escape(APP_NAME)}</div>
        <div class="brand-tagline">{html.escape(APP_TAGLINE)}</div>
        <p class="muted brand-desc">{html.escape(APP_DESCRIPTION)}</p>
      </div>
    </div>
    <h1>Static analysis report</h1>
    <p class="muted">Generated {html.escape(report.generated_at)}</p>

    <div class="grid grid-3">
        <div class="card">
        <h3>APK Summary</h3>
        {self._summary_line("APK", report.project.apk_name)}
        {self._summary_line("Package", report.project.package_name)}
        {self._summary_line("Version", report.project.version_name)}
        {self._summary_line("Version code", report.project.version_code)}
        {self._summary_line("SHA256", report.project.apk_sha256, mono=True)}
        {self._summary_line("Size", self._format_size(report.project.apk_size))}
      </div>
      <div class="card">
        <h3>Run Summary</h3>
        {self._summary_line("Run ID", report.run.run_id, mono=True)}
        {self._summary_line("Status", report.run.status)}
        {self._summary_line("Started", report.run.started_at)}
        {self._summary_line("Finished", report.run.finished_at)}
        {self._summary_line("Duration", self._format_duration(report.run.duration_sec))}
      </div>
      <div class="card">
        <h3>Findings</h3>
        {self._summary_line("Total", str(context["total_findings"]))}
        {self._summary_line("High", str(context["severity_counts"]["high"]))}
        {self._summary_line("Medium", str(context["severity_counts"]["medium"]))}
        {self._summary_line("Low", str(context["severity_counts"]["low"]))}
        {self._summary_line("Info", str(context["severity_counts"]["info"]))}
      </div>
    </div>

    <h2>Tool status</h2>
    <div class="grid grid-3">
      {context["tool_cards"]}
    </div>

    <h2>Project and run info</h2>
    <div class="card">
      {self._summary_line("Project ID", report.project.project_id, mono=True)}
      {self._summary_line("APK path", report.project.apk_path, copyable=True, mono=True)}
      {self._summary_line("Run dir", report.run.run_dir, copyable=True, mono=True)}
    </div>

    <h2>What was analyzed</h2>
    <div class="grid grid-3">
      <div class="card">
        <h3>Manifest analysis</h3>
        <p class="muted">Permissions, exported components, and security flags.</p>
        <div class="muted">Permissions:</div>
        {context["manifest_info"]}
        <div class="muted">Exported:</div>
        {context["exported_info"]}
        <div class="muted">Flags:</div>
        {context["flags_info"]}
      </div>
        <div class="card">
        <h3>Code indicators</h3>
        <p class="muted">JADX/smali/YARA indicators for sensitive behaviors.</p>
        <p>YARA matches: {context["yara_matches"]}</p>
      </div>
        <div class="card">
        <h3>Endpoints & signing</h3>
        <p class="muted">Endpoint extraction is pattern-based and may include noise.</p>
        <p>URLs: {report.endpoints_summary.get("urls", 0)}; IPs: {report.endpoints_summary.get("ips", 0)}</p>
        <p>Signing issues: {context["signing_issues"]}</p>
      </div>
    </div>

    <h2>Extracted endpoints (rg)</h2>
    {context["endpoints_section"]}

    <h2>Findings</h2>
    <div class="filters">
      <select id="severityFilter">
        <option value="all">All severities</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
      </select>
      <input type="text" id="searchInput" placeholder="Search findings"/>
      {context["show_more_low_info"]}
    </div>
    {context["findings_sections"] or '<p class="muted">No findings.</p>'}

    <h2>Artifacts</h2>
    <div class="card">
      {context["artifacts"] or '<p class="muted">No artifacts found.</p>'}
    </div>
  </div>

  <script>
    const severityFilter = document.getElementById('severityFilter');
    const searchInput = document.getElementById('searchInput');
    const rows = document.querySelectorAll('.findings-table tbody tr');

    function isHidden(row) {{
      return row.dataset.hiddenGlobal === '1' || row.dataset.hiddenCategory === '1';
    }}

    function applyFilters() {{
      const severity = severityFilter.value;
      const query = searchInput.value.toLowerCase();
      rows.forEach(row => {{
        const rowSeverity = row.getAttribute('data-severity');
        const text = row.getAttribute('data-text');
        const matchesSeverity = severity === 'all' || rowSeverity === severity;
        const matchesQuery = !query || text.includes(query);
        const visible = matchesSeverity && matchesQuery && !isHidden(row);
        row.style.display = visible ? '' : 'none';
      }});
    }}
    severityFilter.addEventListener('change', applyFilters);
    searchInput.addEventListener('input', applyFilters);

    const showMoreLowInfo = document.getElementById('showMoreLowInfo');
    if (showMoreLowInfo) {{
      showMoreLowInfo.addEventListener('click', () => {{
        rows.forEach(row => {{
          if (row.dataset.hiddenGlobal === '1') {{
            row.dataset.hiddenGlobal = '0';
          }}
        }});
        showMoreLowInfo.style.display = 'none';
        applyFilters();
      }});
    }}

    document.querySelectorAll('.show-more-category').forEach(button => {{
      button.addEventListener('click', () => {{
        const category = button.dataset.category;
        rows.forEach(row => {{
          if (row.dataset.category === category) {{
            row.dataset.hiddenCategory = '0';
            row.dataset.hiddenGlobal = '0';
          }}
        }});
        button.style.display = 'none';
        applyFilters();
      }});
    }});

    const endpointSearch = document.getElementById('endpointSearch');
    const endpointHideNoise = document.getElementById('endpointHideNoise');
    const endpointRows = document.querySelectorAll('#endpointTable tbody tr');

    function applyEndpointFilters() {{
      const query = endpointSearch ? endpointSearch.value.toLowerCase() : '';
      const hideNoise = endpointHideNoise ? endpointHideNoise.checked : false;
      endpointRows.forEach(row => {{
        const value = row.getAttribute('data-value') || '';
        const noise = row.getAttribute('data-noise') === '1';
        const matchesQuery = !query || value.includes(query);
        const visible = matchesQuery && (!hideNoise || !noise);
        row.style.display = visible ? '' : 'none';
      }});
    }}

    if (endpointSearch) {{
      endpointSearch.addEventListener('input', applyEndpointFilters);
    }}
    if (endpointHideNoise) {{
      endpointHideNoise.addEventListener('change', applyEndpointFilters);
    }}

    document.querySelectorAll('.copy-btn').forEach(button => {{
      button.addEventListener('click', () => {{
        const text = button.getAttribute('data-copy');
        navigator.clipboard.writeText(text);
        button.textContent = 'Copied';
        setTimeout(() => button.textContent = 'Copy', 1200);
      }});
    }});

    applyFilters();
    applyEndpointFilters();
  </script>
</body>
</html>
"""

    def _build_context(self, report: Stage1ReportModel) -> dict[str, object]:
        severity_counts = self._severity_counts(report.findings)
        url_map, ip_map = _collect_endpoints(report.findings)
        findings_sections, show_more_low_info = self._render_findings_sections(report.findings)
        return {
            "severity_counts": severity_counts,
            "total_findings": len(report.findings),
            "tool_cards": self._render_tool_cards(report.tool_statuses),
            "findings_sections": findings_sections,
            "show_more_low_info": show_more_low_info,
            "artifacts": self._render_artifacts(report.artifacts, report.run.run_dir),
            "yara_matches": self._format_tool_value(report.tool_statuses, "yara", "matches"),
            "signing_issues": sum(report.signing_summary.values()),
            "endpoints_section": self._endpoint_section(report, url_map, ip_map),
            "manifest_info": self._render_list(report.manifest_permissions),
            "exported_info": self._render_list(report.manifest_exported),
            "flags_info": self._render_list(report.manifest_flags),
            "brand_logo": self._render_brand_logo(),
        }

    def _severity_counts(self, findings: list[Finding]) -> dict[str, int]:
        counts = {level: 0 for level in SEVERITY_ORDER}
        for finding in findings:
            level = (finding.severity or "info").lower()
            if level in counts:
                counts[level] += 1
        return counts

    def _render_tool_cards(self, tool_statuses: list[ToolStatus]) -> str:
        cards = []
        for tool in tool_statuses:
            cards.append(
                f"""
                <div class="card tool-card">
                  <div class="tool-title">{html.escape(tool.tool.upper())}</div>
                  <div class="tool-status status-{tool.status}">{html.escape(tool.status)}</div>
                  <div class="tool-details">{html.escape(tool.details or '-')}</div>
                </div>
                """
            )
        return "".join(cards)

    def _render_findings_sections(self, findings: list[Finding]) -> tuple[str, str]:
        findings_state = {
            "low_info_limit": 50,
            "category_limit": 20,
            "low_info_seen": 0,
            "has_hidden_global": False,
        }
        findings_by_category = self._group_findings(findings)
        findings_sections = []
        for category, entries in findings_by_category:
            description = CATEGORY_DESCRIPTIONS.get(
                category,
                "Indicators discovered for this category.",
            )
            description = f"{description} Validate in app context to reduce false positives."
            table_html, has_hidden_category = self._findings_table(
                category,
                entries,
                findings_state,
            )
            show_more_button = ""
            if has_hidden_category:
                show_more_button = (
                    f'<button class="ghost-btn show-more-category" '
                    f'data-category="{html.escape(category)}">Show more</button>'
                )
            findings_sections.append(
                f"""
                <div class="category-block">
                  <h4>{html.escape(category)}</h4>
                  <p class="muted">{html.escape(description)}</p>
                  {show_more_button}
                  {table_html}
                </div>
                """
            )
        show_more_low_info = (
            '<button id="showMoreLowInfo" class="ghost-btn">Show more low/info</button>'
            if findings_state["has_hidden_global"]
            else ""
        )
        return "".join(findings_sections), show_more_low_info

    def _render_artifacts(self, artifacts: list[str], run_dir: str | None) -> str:
        rows = []
        for path in artifacts:
            escaped_path = html.escape(path)
            copy_path = path
            if run_dir:
                suffix = "/" if path.endswith("/") else ""
                rel = path.rstrip("/")
                copy_path = str(Path(run_dir) / rel) + suffix
            rows.append(
                f"""
                <div class="artifact-row">
                  <span class="artifact-path">{escaped_path}</span>
                  <button class="copy-btn" data-copy="{html.escape(copy_path)}">Copy</button>
                </div>
                """
            )
        return "".join(rows)

    def _format_tool_value(self, tool_statuses: list[ToolStatus], tool: str, key: str) -> str:
        value = self._tool_value(tool_statuses, tool, key)
        return "-" if value is None else str(value)

    def _render_brand_logo(self) -> str:
        logo_uri = _logo_data_uri()
        if not logo_uri:
            return ""
        return f'<img class="brand-logo" src="{logo_uri}" alt="{APP_NAME} logo"/>'

    def _summary_line(
        self,
        label: str,
        value: str | None,
        copyable: bool = False,
        mono: bool = False,
    ) -> str:
        safe_value = html.escape(value or "-")
        safe_label = html.escape(label)
        copy_button = ""
        if copyable and value:
            copy_button = (
                f' <button class="copy-btn" data-copy="{html.escape(value)}">Copy</button>'
            )
        mono_class = " mono" if mono else ""
        return (
            f'<div class="summary-line"><span class="summary-label">{safe_label}</span>'
            f'<span class="summary-value{mono_class}">'
            f'<span class="summary-text">{safe_value}</span>{copy_button}</span></div>'
        )

    def _format_duration(self, seconds: float | None) -> str:
        if seconds is None:
            return "-"
        minutes, secs = divmod(int(seconds), 60)
        if minutes:
            return f"{minutes}m {secs}s"
        return f"{secs}s"

    def _format_size(self, size: int | None) -> str:
        if size is None:
            return "-"
        value = float(size)
        for unit in ["B", "KB", "MB", "GB"]:
            if value < 1024:
                return f"{value:.0f} {unit}"
            value /= 1024
        return f"{value:.0f} TB"

    def _render_list(self, items: list[str]) -> str:
        if not items:
            return "<p class=\"muted\">None</p>"
        return "<ul>" + "".join(f"<li>{html.escape(item)}</li>" for item in items) + "</ul>"

    def _artifact_path(self, run_dir: str | None, filename: str) -> str:
        if not run_dir:
            return f"artifacts/{filename}"
        return str(Path(run_dir) / "artifacts" / filename)

    def _endpoint_section(
        self,
        report: Stage1ReportModel,
        url_map: dict[str, dict],
        ip_map: dict[str, dict],
    ) -> str:
        total_urls = len(url_map)
        total_ips = len(ip_map)
        if total_urls == 0 and total_ips == 0:
            return '<p class="muted">No endpoints extracted by rg.</p>'

        entries = []
        for value, entry in url_map.items():
            example = entry["examples"][0] if entry["examples"] else None
            entries.append(
                {
                    "type": "URL",
                    "value": value,
                    "example": _format_example_location(example),
                    "noise": bool(entry.get("noise")),
                }
            )
        for value, entry in ip_map.items():
            example = entry["examples"][0] if entry["examples"] else None
            entries.append(
                {
                    "type": "IP",
                    "value": value,
                    "example": _format_example_location(example),
                    "noise": False,
                }
            )
        entries.sort(key=lambda item: (item["noise"], item["value"].lower()))
        entries = entries[:ENDPOINT_TOP_N]

        rows = []
        for entry in entries:
            value_raw = entry["value"]
            value = html.escape(value_raw)
            example = html.escape(entry["example"])
            noise_flag = "1" if entry["noise"] else "0"
            rows.append(
                f"""
                <tr data-noise="{noise_flag}" data-value="{html.escape(value_raw.lower())}">
                  <td>{html.escape(entry["type"])}</td>
                  <td><pre class="cell-pre mono">{value}</pre></td>
                  <td><pre class="cell-pre">{example}</pre></td>
                </tr>
                """
            )

        urls_path = self._artifact_path(report.run.run_dir, "endpoints.urls.txt")
        ips_path = self._artifact_path(report.run.run_dir, "endpoints.ips.txt")
        urls_json_path = self._artifact_path(report.run.run_dir, "endpoints.urls.json")
        ips_json_path = self._artifact_path(report.run.run_dir, "endpoints.ips.json")

        files_html = (
            self._summary_line("URLs list", urls_path, copyable=True, mono=True)
            + self._summary_line("IPs list", ips_path, copyable=True, mono=True)
            + self._summary_line("URLs JSON", urls_json_path, copyable=True, mono=True)
            + self._summary_line("IPs JSON", ips_json_path, copyable=True, mono=True)
        )

        return f"""
        <div class="card">
          <p class="muted">Static extraction of endpoint-like strings. Noise is expected.</p>
          <p class="muted">Unique URLs: {total_urls}; IPs: {total_ips}. Showing up to {len(entries)}.</p>
          <div class="endpoint-controls">
            <input type="text" id="endpointSearch" placeholder="Search endpoints"/>
            <label><input type="checkbox" id="endpointHideNoise" checked/> Hide noise</label>
          </div>
          {files_html}
          <table id="endpointTable">
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Example location</th>
              </tr>
            </thead>
            <tbody>
              {''.join(rows)}
            </tbody>
          </table>
        </div>
        """

    def _tool_value(self, tools: list[ToolStatus], name: str, attr: str):
        for tool in tools:
            if tool.tool == name:
                return getattr(tool, attr, None)
        return None

    def _group_findings(self, findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
        categories = {}
        for finding in findings:
            label = self._category_label(finding)
            categories.setdefault(label, []).append(finding)
        ordered = []
        def severity_rank(value: str) -> int:
            value = value.lower()
            if value in SEVERITY_ORDER:
                return SEVERITY_ORDER.index(value)
            return len(SEVERITY_ORDER)

        category_items = []
        for category, entries in categories.items():
            highest = min(
                (severity_rank((entry.severity or "info")) for entry in entries),
                default=len(SEVERITY_ORDER),
            )
            category_items.append((highest, category, entries))

        for _, category, entries in sorted(category_items, key=lambda item: (item[0], item[1])):
            entries = sorted(
                categories[category],
                key=lambda f: SEVERITY_ORDER.index((f.severity or "info").lower())
                if (f.severity or "info").lower() in SEVERITY_ORDER
                else len(SEVERITY_ORDER),
            )
            ordered.append((category, entries))
        return ordered

    def _category_label(self, finding: Finding) -> str:
        if finding.category == "secret_endpoints_hardcoded":
            sources = finding.sources or []
            if any(source.startswith("rg:endpoint_") for source in sources):
                return "indicator_endpoints_hardcoded"
        return finding.category

    def _findings_table(
        self,
        category_label: str,
        findings: list[Finding],
        state: dict,
    ) -> tuple[str, bool]:
        rows = []
        low_info_seen_by_category = 0
        has_hidden_category = False
        for finding in findings:
            severity = (finding.severity or "info").lower()
            hidden_global = False
            hidden_category = False
            if severity in ("low", "info"):
                if state["low_info_seen"] >= state["low_info_limit"]:
                    hidden_global = True
                    state["has_hidden_global"] = True
                else:
                    state["low_info_seen"] += 1
                if low_info_seen_by_category >= state["category_limit"]:
                    hidden_category = True
                else:
                    low_info_seen_by_category += 1
            if hidden_global or hidden_category:
                has_hidden_category = True
            badge = f'<span class="badge badge-{severity}">{html.escape(severity)}</span>'
            evidence = html.escape(finding.evidence or finding.match or "-")
            sources = html.escape(", ".join(finding.sources or []))
            location = html.escape(finding.location or finding.file_path or "-")
            display_category = html.escape(category_label)
            searchable = " ".join(
                [
                    category_label,
                    severity,
                    finding.evidence or "",
                    finding.match or "",
                    location,
                ]
            ).lower()
            rows.append(
                f"""
                <tr data-severity="{severity}"
                    data-category="{html.escape(category_label)}"
                    data-hidden-global="{'1' if hidden_global else '0'}"
                    data-hidden-category="{'1' if hidden_category else '0'}"
                    data-text="{html.escape(searchable)}">
                  <td>{badge}</td>
                  <td>{display_category}</td>
                  <td><pre class="cell-pre">{location}</pre></td>
                  <td><pre class="cell-pre">{evidence}</pre></td>
                  <td><pre class="cell-pre">{sources}</pre></td>
                </tr>
                """
            )
        table = f"""
        <table class="findings-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Title</th>
              <th>Location</th>
              <th>Evidence</th>
              <th>Sources</th>
            </tr>
          </thead>
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
        """
        return table, has_hidden_category

    def _shorten(self, value: str, max_len: int = 120) -> str:
        if len(value) <= max_len:
            return value
        return value[: max_len - 3] + "..."


class StubHtmlRenderer:
    def render(self, report: BaseReportModel, title: str, stage_id: str) -> str:
        sections = {
            STAGE_DYNAMIC: [
                "Emulator/device info",
                "Network capture",
                "Runtime permissions and app ops",
                "Filesystem diff",
                "Runtime events",
            ],
            STAGE_CROSS_TOOL: [
                "External tools (MobSF, etc.)",
                "Correlation and deduplication",
                "Final scoring adjustments",
            ],
            STAGE_OVERALL: [
                "Executive summary",
                "Combined findings",
                "Timeline",
                "Recommendations",
            ],
        }
        planned = sections.get(stage_id, [])
        logo_uri = _logo_data_uri()
        brand_logo = ""
        if logo_uri:
            brand_logo = f'<img class="brand-logo" src="{logo_uri}" alt="{APP_NAME} logo"/>'
        return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>{html.escape(title)}</title>
  <style>
    body {{
      margin: 0;
      font-family: "IBM Plex Sans", "Noto Sans", sans-serif;
      background: #121417;
      color: #e6e9ee;
    }}
    .container {{
      padding: 24px;
    }}
    .report-brand {{
      display: flex;
      gap: 16px;
      align-items: center;
      margin-bottom: 18px;
      padding-bottom: 12px;
      border-bottom: 1px solid #2b3138;
    }}
    .brand-logo {{
      width: 56px;
      height: 56px;
      border-radius: 12px;
      object-fit: contain;
      background: #1b1f24;
      border: 1px solid #2b3138;
      padding: 6px;
    }}
    .brand-name {{
      font-size: 22px;
      font-weight: 700;
      letter-spacing: 0.2px;
    }}
    .brand-tagline {{
      font-size: 13px;
      color: #9aa3ad;
      text-transform: uppercase;
      letter-spacing: 0.12em;
    }}
    .brand-desc {{
      margin: 6px 0 0 0;
    }}
    .card {{
      background: #1b1f24;
      border: 1px solid #2b3138;
      border-radius: 12px;
      padding: 16px;
      margin-top: 16px;
    }}
    .muted {{
      color: #9aa3ad;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="report-brand">
      {brand_logo}
      <div>
        <div class="brand-name">{html.escape(APP_NAME)}</div>
        <div class="brand-tagline">{html.escape(APP_TAGLINE)}</div>
        <p class="muted brand-desc">{html.escape(APP_DESCRIPTION)}</p>
      </div>
    </div>
    <h1>{html.escape(title)}</h1>
    <p class="muted">Not implemented yet.</p>
    <div class="card">
      <h3>Project info</h3>
      <p>Project ID: {html.escape(report.project.project_id)}</p>
      <p>APK: {html.escape(report.project.apk_name or '-')}</p>
      <p>Run ID: {html.escape(report.run.run_id)}</p>
    </div>
    <div class="card">
      <h3>Planned sections</h3>
      <ul>
        {''.join(f"<li>{html.escape(item)}</li>" for item in planned) if planned else "<li>To be defined.</li>"}
      </ul>
    </div>
  </div>
</body>
</html>
"""
