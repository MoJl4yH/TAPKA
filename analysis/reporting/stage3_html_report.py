from __future__ import annotations

import base64
import html
from pathlib import Path

from analysis.models.mobsf import MobSFReport
from models.report import Stage3ReportModel


APP_NAME = "TAPKA"


def _logo_data_uri() -> str | None:
    logo_path = Path(__file__).resolve().parents[2] / "ui" / "87288873-75ab-4871-bf62-f126ff451e6c.png"
    if not logo_path.exists():
        return None
    data = base64.b64encode(logo_path.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{data}"


class Stage3HtmlRenderer:
    def render(self, report: Stage3ReportModel) -> str:
        mobsf = report.mobsf
        static = mobsf.static if mobsf else None
        return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>TAPKA Stage3 Report</title>
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
    h1, h2, h3, h4 {{
      margin: 0 0 12px 0;
    }}
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
      {self._render_logo()}
      <div>
        <div class="brand-name">{html.escape(APP_NAME)}</div>
        <div class="brand-tagline">Cross-tool analysis</div>
        <p class="muted brand-desc">MobSF static analysis summary for comparison.</p>
      </div>
    </div>

    <h1>Cross-tool analysis report</h1>
    <p class="muted">Generated {html.escape(report.generated_at)}</p>

    <div class="grid grid-3">
      <div class="card">
        <h3>APK Summary</h3>
        {self._summary_line("APK", self._value(static, "app_name") or report.project.apk_name)}
        {self._summary_line("Package", self._value(static, "package_name") or report.project.package_name)}
        {self._summary_line("Version", self._value(static, "version_name") or report.project.version_name)}
        {self._summary_line("Version code", self._value(static, "version_code") or report.project.version_code)}
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
        <h3>MobSF Summary</h3>
        {self._summary_line("Security score", self._format_security_score(static))}
        {self._summary_line("Permissions", self._format_number(self._value(static, "permissions_total")))}
        {self._summary_line("Exported", self._format_number(self._value(static, "exported_total")))}
        {self._summary_line("URLs", self._format_number(self._value(static, "urls_total")))}
        {self._summary_line("Trackers", self._format_trackers(static))}
      </div>
    </div>

    <h2>Tool status</h2>
    <div class="grid grid-3">
      {self._render_tool_cards(report.tool_statuses)}
    </div>

    <h2>Project and run info</h2>
    <div class="card">
      {self._summary_line("Project ID", report.project.project_id, mono=True)}
      {self._summary_line("APK path", report.project.apk_path, copyable=True, mono=True)}
      {self._summary_line("Run dir", report.run.run_dir, copyable=True, mono=True)}
    </div>

    <h2>Static analysis highlights</h2>
    {self._render_highlights(static)}

    <h2>MobSF findings</h2>
    {self._render_appsec_findings(static)}

    <h2>Static analysis artifacts</h2>
    <div class="card">
      {self._render_artifacts(mobsf.artifacts.static if mobsf else {}, report.run.run_dir)}
    </div>

    <h2>Dynamic Android</h2>
    {self._render_dynamic_android(mobsf, report.run.run_dir)}

    <h2>iOS</h2>
    {self._render_ios(mobsf)}

    {self._render_notes(report.notes)}
  </div>
  <script>
    document.querySelectorAll('.copy-btn').forEach(btn => {{
      btn.addEventListener('click', () => {{
        navigator.clipboard.writeText(btn.dataset.copy);
        btn.textContent = 'Copied';
        setTimeout(() => btn.textContent = 'Copy', 1200);
      }});
    }});

    const showOtherFindings = document.getElementById('showOtherFindings');
    if (showOtherFindings) {{
      showOtherFindings.addEventListener('click', () => {{
        const hidden = document.getElementById('otherFindings');
        if (hidden) {{
          hidden.style.display = 'block';
        }}
        showOtherFindings.style.display = 'none';
      }});
    }}
  </script>
</body>
</html>
"""

    def _render_logo(self) -> str:
        logo_uri = _logo_data_uri()
        if not logo_uri:
            return ""
        return f'<img class="brand-logo" src="{logo_uri}" alt="{APP_NAME} logo"/>'

    def _render_highlights(self, static) -> str:
        if not static:
            return '<div class="card muted">No MobSF data.</div>'
        permissions = self._render_list(static.permissions_top)
        exported = self._render_list(static.exported_top)
        urls = self._render_list(static.urls_top)
        domains = self._render_list(static.domains_top)
        trackers = self._render_list(static.trackers_top)
        manifest_summary = self._render_summary_table(static.manifest_summary)
        code_summary = self._render_summary_table(static.code_summary)
        secrets = self._format_number(static.secrets_total)
        crypto = self._format_number(static.crypto_total)
        return f"""
        <div class="grid grid-3">
          <div class="card">
            <h3>Permissions & Exported</h3>
            {self._summary_line("Permissions", self._format_number(static.permissions_total))}
            {self._summary_line("Exported", self._format_number(static.exported_total))}
            <div class="muted">Top permissions</div>
            {permissions}
            <div class="muted">Top exported</div>
            {exported}
          </div>
          <div class="card">
            <h3>Code & Manifest Summary</h3>
            <div class="muted">Manifest findings</div>
            {manifest_summary}
            <div class="muted">Code findings</div>
            {code_summary}
            {self._summary_line("Secrets", secrets)}
            {self._summary_line("Crypto indicators", crypto)}
          </div>
          <div class="card">
            <h3>Network & Trackers</h3>
            {self._summary_line("URLs", self._format_number(static.urls_total))}
            {self._summary_line("Domains", self._format_number(static.domains_total))}
            {self._summary_line("Trackers", self._format_trackers(static))}
            <div class="muted">Top URLs</div>
            {urls}
            <div class="muted">Top domains</div>
            {domains}
            <div class="muted">Top trackers</div>
            {trackers}
          </div>
        </div>
        """

    def _render_appsec_findings(self, static) -> str:
        if not static:
            return '<div class="card muted">No MobSF findings.</div>'
        high_rows = self._render_appsec_rows(static.appsec_high)
        warning_rows = self._render_appsec_rows(static.appsec_warning)
        info_rows = self._render_appsec_rows(static.appsec_info)
        secure_rows = self._render_appsec_rows(static.appsec_secure)
        hotspot_rows = self._render_appsec_rows(static.appsec_hotspot)
        if not high_rows and not warning_rows and not info_rows and not secure_rows and not hotspot_rows:
            return '<div class="card muted">No MobSF findings.</div>'
        other_block = ""
        if warning_rows or info_rows or secure_rows or hotspot_rows:
            other_block = f"""
            <button id="showOtherFindings" class="ghost-btn">Show other findings</button>
            <div id="otherFindings" style="display:none;">
              {self._render_appsec_table("Warnings", warning_rows)}
              {self._render_appsec_table("Info", info_rows)}
              {self._render_appsec_table("Secure", secure_rows)}
              {self._render_appsec_table("Hotspots", hotspot_rows)}
            </div>
            """
        return f"""
        <div class="card">
          {self._render_appsec_table("High", high_rows)}
          {other_block}
        </div>
        """

    def _render_appsec_table(self, title: str, rows: str) -> str:
        if not rows:
            return ""
        return f"""
        <h4>{html.escape(title)}</h4>
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Section</th>
              <th>Title</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {rows}
          </tbody>
        </table>
        """

    def _render_appsec_rows(self, items: list) -> str:
        rows = []
        for item in items or []:
            severity = html.escape(item.severity.upper())
            section = html.escape(item.section or "N/A")
            title = html.escape(item.title)
            description = html.escape(item.description or "-")
            rows.append(
                f"<tr><td>{severity}</td><td>{section}</td><td>{title}</td><td>{description}</td></tr>"
            )
        return "".join(rows)

    def _render_dynamic_android(self, mobsf: MobSFReport | None, run_dir: str | None) -> str:
        if not mobsf or not mobsf.dynamic_android.enabled:
            return '<div class="card muted">Not configured.</div>'
        dynamic = mobsf.dynamic_android
        artifacts = self._render_artifacts(mobsf.artifacts.dynamic_android, run_dir)
        tls = self._render_summary_table(dynamic.tls_tests)
        frida = self._render_summary_table(dynamic.frida)
        return f"""
        <div class="card">
          {self._summary_line("Status", dynamic.status or "N/A")}
          {self._summary_line("Logcat lines", self._format_number(dynamic.logcat_lines))}
          <div class="muted">TLS tests</div>
          {tls}
          <div class="muted">Frida</div>
          {frida}
          <div class="muted">Artifacts</div>
          {artifacts}
        </div>
        """

    def _render_ios(self, mobsf: MobSFReport | None) -> str:
        if not mobsf or not mobsf.ios.enabled:
            return '<div class="card muted">Not configured.</div>'
        rows = [("Status", mobsf.ios.status or "N/A")]
        return f"<div class='card'>{self._render_table(rows)}</div>"

    def _render_notes(self, notes: list[str]) -> str:
        if not notes:
            return ""
        items = "".join(f"<li>{html.escape(note)}</li>" for note in notes)
        return f"""
        <h2>Notes</h2>
        <div class="card"><ul>{items}</ul></div>
        """

    def _render_artifacts(self, artifacts: dict[str, str], run_dir: str | None) -> str:
        if not artifacts:
            return "<div class='muted'>No artifacts.</div>"
        rows = []
        for label, path in artifacts.items():
            copy_path = path
            if run_dir:
                suffix = "/" if path.endswith("/") else ""
                rel = path.rstrip("/")
                copy_path = str(Path(run_dir) / rel) + suffix
            rows.append(
                f"""
                <div class="artifact-row">
                  <span class="artifact-path">{html.escape(label)}: {html.escape(path)}</span>
                  <button class="copy-btn" data-copy="{html.escape(copy_path)}">Copy</button>
                </div>
                """
            )
        return "".join(rows)

    def _render_tool_cards(self, tool_statuses) -> str:
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
            copy_button = f' <button class="copy-btn" data-copy="{html.escape(value)}">Copy</button>'
        mono_class = " mono" if mono else ""
        return (
            f'<div class="summary-line"><span class="summary-label">{safe_label}</span>'
            f'<span class="summary-value{mono_class}">'
            f'<span class="summary-text">{safe_value}</span>{copy_button}</span></div>'
        )

    def _render_list(self, items: list[str]) -> str:
        if not items:
            return "<p class=\"muted\">N/A</p>"
        return "<ul>" + "".join(f"<li>{html.escape(item)}</li>" for item in items) + "</ul>"

    def _render_summary_table(self, data: dict[str, int | str | float]) -> str:
        if not data:
            return "<div class='muted'>N/A</div>"
        rows = "".join(
            f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>"
            for k, v in data.items()
        )
        return f"<table>{rows}</table>"

    def _format_trackers(self, static) -> str:
        if not static:
            return "N/A"
        detected = static.trackers_detected
        total = static.trackers_total
        if detected is not None and total is not None:
            return f"{detected}/{total}"
        if total is not None:
            return str(total)
        return "N/A"

    def _format_number(self, value) -> str:
        if value is None:
            return "N/A"
        return str(value)

    def _format_security_score(self, static) -> str:
        if not static or static.security_score is None:
            return "N/A"
        return f"{static.security_score}/100"

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

    def _value(self, static, field: str) -> str | None:
        if not static:
            return None
        value = getattr(static, field, None)
        if value is None:
            return None
        return str(value)
