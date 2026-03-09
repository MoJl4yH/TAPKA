from __future__ import annotations

import base64
import html
from collections import Counter
from pathlib import Path

from analysis.stages import STAGE_CROSS_TOOL, STAGE_DYNAMIC, STAGE_OVERALL, STAGE_STATIC
from models.report_v2 import FindingV2, ReportV2


APP_NAME = "TAPKA"
TOP_ENDPOINT_URLS = 20
TOP_ENDPOINT_IPS = 10
TOP_FINDINGS = 15
TOP_ARTIFACTS = 40

SIGNING_CATEGORIES = {"supplychain_*"}
SECRET_CATEGORIES = {"secret_*"}
VULNERABILITY_CATEGORIES = {"vul_*", "sec_*"}
NDV_CATEGORIES = {"ndv_*"}
ANOMALY_CATEGORIES = {"anomaly_*"}
DYNAMIC_LOAD_CATEGORIES = {
    "ndv_dynamic_code_loading",
    "ndv_native_code_loader_suspicious",
    "ndv_reflection_heavy",
    "ndv_download_execute",
}
SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}

SECTION_DESCRIPTIONS = {
    "identification": "Identification metadata for reproducible APK analysis.",
    "signing": "APK signature and certificate details: schemes, signer identity, and cryptographic properties.",
    "manifest": "App manifest metadata: permissions, exported components, and security flags.",
    "string_screening": "Static string and signature screening of decoded APK content.",
    "endpoints": "External endpoints (URL, IPv4) found in code and resources.",
    "secrets": "Potential hardcoded sensitive data: keys, tokens, passwords, and JWT.",
    "dynamic_load": "Indicators of dynamic code loading and OS command execution.",
    "anti_analysis": "Anti-analysis indicators: emulator, root, Frida, and debugger checks.",
    "ndv_capabilities": "Potential undeclared capabilities: remote control, interception, and surveillance.",
    "yara_screening": "YARA signature screening results.",
    "vulnerabilities": "Configuration weaknesses and unsafe implementation patterns.",
    "native_strings": "Indicators found in extracted native library (.so) strings.",
    "network_activity": "Observed network activity during dynamic analysis.",
    "install_changes": "File system and system state changes after APK installation.",
    "runtime_behavior": "Runtime behavior: services, receivers, and errors.",
    "mobsf": "MobSF results: security score, findings, and configuration signals.",
    "quark": "Quark behavioral analysis results and matched rules.",
    "apkid": "Detected packers, obfuscators, and protection mechanisms (APKiD).",
    "apkleaks": "Potential leaked secrets and configuration values (APKLeaks).",
    "overall_verdict": "Final assessment using the project two-level decision model.",
}

REPORT_TITLES = {
    STAGE_STATIC: "Static Expert-Assisted Analysis Report (Stage 1)",
    STAGE_DYNAMIC: "Dynamic Expert-Assisted Analysis Report (Stage 2)",
    STAGE_CROSS_TOOL: "Cross-Tool Analysis Report (Stage 3)",
    STAGE_OVERALL: "Final Expert Assessment for Android Application Analysis",
}


def _logo_data_uri() -> str | None:
    logo_path = Path(__file__).resolve().parents[2] / "ui" / "87288873-75ab-4871-bf62-f126ff451e6c.png"
    if not logo_path.exists():
        return None
    data = base64.b64encode(logo_path.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{data}"


def _fmt(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".")
    return str(value)


def _status_class(status: str | None) -> str:
    value = (status or "").strip().lower().replace(" ", "_")
    return value or "unknown"


def _severity_class(severity: str | None) -> str:
    return f"sev-{(severity or 'info').strip().lower()}"


def _category_matches(category: str, patterns: set[str]) -> bool:
    for pattern in patterns:
        if pattern.endswith("*"):
            if category.startswith(pattern[:-1]):
                return True
            continue
        if category == pattern:
            return True
    return False


def _finding_evidence_snippet(finding: FindingV2) -> str:
    if not finding.evidence:
        return ""
    first = finding.evidence[0]
    return str(first.snippet or first.ref or first.file or "")


def _finding_location(finding: FindingV2) -> str:
    if not finding.evidence:
        return "-"
    first = finding.evidence[0]
    if first.file and first.line:
        return f"{first.file}:{first.line}"
    return str(first.file or first.ref or "-")


def _section_map(report: ReportV2) -> dict[str, object]:
    return {section.id: section for section in report.sections}


def _sort_findings(findings: list[FindingV2]) -> list[FindingV2]:
    confidence_rank = {"C3": 3, "C2": 2, "C1": 1}
    return sorted(
        findings,
        key=lambda item: (
            -SEVERITY_RANK.get(item.severity, 0),
            -confidence_rank.get(item.confidence, 0),
            item.category,
            item.title,
        ),
    )


def _filter_findings(
    findings: list[FindingV2],
    include_patterns: set[str] | None = None,
    exclude_patterns: set[str] | None = None,
) -> list[FindingV2]:
    output: list[FindingV2] = []
    for finding in findings:
        category = finding.category or ""
        if include_patterns and not _category_matches(category, include_patterns):
            continue
        if exclude_patterns and _category_matches(category, exclude_patterns):
            continue
        output.append(finding)
    return output


def _card(section_id: str, title: str, body_html: str, description: str | None = None) -> tuple[str, str, str]:
    description_html = f"<p class='muted section-desc'>{html.escape(description)}</p>" if description else ""
    card_html = (
        f"<section id='{html.escape(section_id)}' class='card'>"
        f"<h2>{html.escape(title)}</h2>"
        f"{description_html}"
        f"{body_html}"
        "</section>"
    )
    return section_id, title, card_html


def _rows_table(
    headers: list[str],
    rows: list[list[str]],
    empty_text: str,
    table_id: str,
    limit: int | None = None,
) -> str:
    if not rows:
        colspan = len(headers)
        return (
            "<table><thead><tr>"
            + "".join(f"<th>{html.escape(header)}</th>" for header in headers)
            + f"</tr></thead><tbody><tr><td colspan='{colspan}' class='muted'>{html.escape(empty_text)}</td></tr></tbody></table>"
        )

    visible = rows
    hidden: list[list[str]] = []
    if isinstance(limit, int) and limit > 0 and len(rows) > limit:
        visible = rows[:limit]
        hidden = rows[limit:]

    table = "<table><thead><tr>" + "".join(f"<th>{html.escape(header)}</th>" for header in headers) + "</tr></thead><tbody>"
    for row in visible:
        table += "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
    table += "</tbody>"

    if hidden:
        table += f"<tbody id='{html.escape(table_id)}-extra' class='hidden'>"
        for row in hidden:
            table += "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
        table += "</tbody>"
    table += "</table>"

    if hidden:
        table += (
            f"<button class='btn-link' onclick=\"tapkaToggle('{html.escape(table_id)}-extra', this)\">"
            f"Show all ({len(rows)})</button>"
        )
    return table


def _artifacts_table(report: ReportV2, limit: int = TOP_ARTIFACTS) -> str:
    rows: list[list[str]] = []
    for artifact in report.artifacts:
        button = (
            f"<button class='btn-mini' onclick=\"tapkaCopy('{html.escape(artifact.path)}')\">Copy</button>"
        )
        rows.append(
            [
                html.escape(artifact.kind),
                html.escape(artifact.name),
                f"<span class='mono'>{html.escape(artifact.path)}</span>",
                html.escape(_fmt(artifact.size)),
                html.escape(_fmt(artifact.mime)),
                button,
            ]
        )
    return _rows_table(
        ["Type", "Name", "Path", "Size", "MIME", "Action"],
        rows,
        "No artifacts.",
        "artifacts",
        limit=limit,
    )


def _tools_table(report: ReportV2, limit: int = 12) -> str:
    rows: list[list[str]] = []
    for tool in report.tools:
        metrics = "<br/>".join(
            f"<span class='mono'>{html.escape(str(key))}</span>: {html.escape(_fmt(value))}"
            for key, value in sorted((tool.metrics or {}).items())
        ) or "-"
        rows.append(
            [
                html.escape(tool.tool),
                f"<span class='status-{_status_class(tool.status)}'>{html.escape(tool.status)}</span>",
                html.escape(_fmt(tool.duration_ms)),
                metrics,
            ]
        )
    return _rows_table(["Tool", "Status", "Duration ms", "Metrics"], rows, "No tools recorded.", "tools", limit)


def _identification_table(report: ReportV2) -> str:
    rows = [
        ["APK file", html.escape(_fmt(report.project.apk_name))],
        ["SHA-256", f"<span class='mono'>{html.escape(_fmt(report.project.apk_sha256))}</span>"],
        ["Size", html.escape(_fmt(report.project.apk_size))],
        ["Package", html.escape(_fmt(report.project.package_name))],
        ["Version Name", html.escape(_fmt(report.project.version_name))],
        ["Version Code", html.escape(_fmt(report.project.version_code))],
        ["Run ID", html.escape(report.run.run_id)],
        ["Generated", html.escape(_fmt(report.generated_at))],
    ]
    table = "<table><tbody>"
    for key, value in rows:
        table += f"<tr><th>{html.escape(key)}</th><td>{value}</td></tr>"
    table += "</tbody></table>"
    return table


def _severity_summary(report: ReportV2) -> str:
    counter = Counter(item.severity for item in report.findings)
    rows = [
        [f"<span class='{_severity_class(severity)}'>{severity}</span>", html.escape(str(counter.get(severity, 0)))]
        for severity in ("high", "medium", "low", "info")
    ]
    return _rows_table(["Severity", "Count"], rows, "No findings.", "severity-summary")


def _category_top_table(findings: list[FindingV2], limit: int = 15) -> str:
    grouped: dict[str, dict] = {}
    for finding in findings:
        entry = grouped.setdefault(
            finding.category,
            {
                "count": 0,
                "severity": "info",
                "examples": [],
            },
        )
        entry["count"] += 1
        if SEVERITY_RANK.get(finding.severity, 0) > SEVERITY_RANK.get(entry["severity"], 0):
            entry["severity"] = finding.severity
        snippet = _finding_evidence_snippet(finding)
        if snippet and snippet not in entry["examples"] and len(entry["examples"]) < 2:
            entry["examples"].append(snippet[:120])

    ordered = sorted(
        grouped.items(),
        key=lambda item: (-SEVERITY_RANK.get(item[1]["severity"], 0), -item[1]["count"], item[0]),
    )
    rows: list[list[str]] = []
    for category, payload in ordered:
        rows.append(
            [
                html.escape(category),
                f"<span class='{_severity_class(payload['severity'])}'>{html.escape(payload['severity'])}</span>",
                html.escape(str(payload["count"])),
                "<br/>".join(html.escape(value) for value in payload["examples"]) or "-",
            ]
        )
    return _rows_table(["Category", "Max severity", "Count", "Examples"], rows, "No category data.", "category-top", limit)


def _findings_table(findings: list[FindingV2], table_id: str, limit: int = TOP_FINDINGS) -> str:
    rows: list[list[str]] = []
    for finding in _sort_findings(findings):
        rows.append(
            [
                f"<span class='{_severity_class(finding.severity)}'>{html.escape(finding.severity)}</span>",
                html.escape(finding.category),
                html.escape(finding.title),
                html.escape(_finding_location(finding)),
                html.escape(_finding_evidence_snippet(finding)[:160]) or "-",
            ]
        )
    return _rows_table(["Severity", "Category", "Title", "Location", "Evidence"], rows, "No findings.", table_id, limit)


def _notes_block(report: ReportV2) -> str:
    if not report.notes:
        return "<p class='muted'>No notes.</p>"
    rows = "".join(f"<li>{html.escape(note)}</li>" for note in report.notes)
    return f"<ul>{rows}</ul>"


def _render_stage1(report: ReportV2) -> list[tuple[str, str, str]]:
    sections: list[tuple[str, str, str]] = []
    section_by_id = _section_map(report)

    sections.append(
        _card(
            "s1-identification",
            "1.1 Analysis Target Identification",
            _identification_table(report),
            SECTION_DESCRIPTIONS["identification"],
        )
    )

    sections.append(
        _card(
            "s1-tools",
            "1.2 Tool Status",
            _tools_table(report),
            "Tool execution status and key metrics for static analysis.",
        )
    )

    signing_section = section_by_id.get("signing_details")
    signing_payload = signing_section.data if signing_section else {}
    signing_payload = signing_payload if isinstance(signing_payload, dict) else {}
    schemes = signing_payload.get("schemes") if isinstance(signing_payload.get("schemes"), dict) else {}
    cert = signing_payload.get("certificate") if isinstance(signing_payload.get("certificate"), dict) else {}
    scheme_rows = [[html.escape(name), html.escape(str(value))] for name, value in sorted(schemes.items())]
    cert_rows = [[html.escape(name), html.escape(_fmt(value))] for name, value in sorted(cert.items())]
    signing_findings = _filter_findings(report.findings, SIGNING_CATEGORIES)
    signing_html = ""
    signing_html += "<h3>Signature Schemes</h3>" + _rows_table(["Scheme", "Enabled"], scheme_rows, "No data.", "sign-schemes")
    signing_html += "<h3>Certificate</h3>" + _rows_table(["Field", "Value"], cert_rows, "No data.", "sign-cert")
    signing_html += "<h3>Signature Issues</h3>" + _findings_table(signing_findings, "sign-findings", limit=10)
    sections.append(_card("s1-signing", "1.3 APK Signature Analysis", signing_html, SECTION_DESCRIPTIONS["signing"]))

    manifest_section = section_by_id.get("manifest")
    manifest = manifest_section.data if manifest_section else {}
    manifest = manifest if isinstance(manifest, dict) else {}
    flags = manifest.get("flags") if isinstance(manifest.get("flags"), list) else []
    permissions = manifest.get("permissions") if isinstance(manifest.get("permissions"), list) else []
    exported = manifest.get("exported") if isinstance(manifest.get("exported"), list) else []
    manifest_html = ""
    manifest_html += _rows_table(
        ["Field", "Value"],
        [
            ["permissions_total", html.escape(str(len(permissions)))],
            ["exported_total", html.escape(str(len(exported)))],
            ["flags_total", html.escape(str(len(flags)))],
        ],
        "No data.",
        "manifest-summary",
    )
    manifest_html += "<h3>Flags</h3>" + _rows_table(["Flag"], [[html.escape(item)] for item in flags], "No flags.", "manifest-flags", 15)
    manifest_html += "<h3>Permissions</h3>" + _rows_table(
        ["Permission"], [[f"<span class='mono'>{html.escape(item)}</span>"] for item in permissions], "No permissions.", "manifest-perm", 20
    )
    manifest_html += "<h3>Exported Components</h3>" + _rows_table(
        ["Component"], [[f"<span class='mono'>{html.escape(item)}</span>"] for item in exported], "No exported components.", "manifest-exp", 15
    )
    sections.append(_card("s1-manifest", "1.4 Manifest and Configuration", manifest_html, SECTION_DESCRIPTIONS["manifest"]))

    urls = [ind for ind in report.indicators if ind.type == "url" and not ind.noise]
    ips = [ind for ind in report.indicators if ind.type == "ip"]
    endpoint_url_rows = []
    for item in urls[:TOP_ENDPOINT_URLS]:
        example = item.examples[0].file if item.examples else "-"
        endpoint_url_rows.append([html.escape(item.value), html.escape(str(len(item.examples or []))), html.escape(_fmt(example))])
    endpoint_ip_rows = []
    for item in ips[:TOP_ENDPOINT_IPS]:
        example = item.examples[0].file if item.examples else "-"
        endpoint_ip_rows.append([html.escape(item.value), html.escape(str(len(item.examples or []))), html.escape(_fmt(example))])

    secrets = _filter_findings(report.findings, SECRET_CATEGORIES)
    dynamic_load = _filter_findings(report.findings, DYNAMIC_LOAD_CATEGORIES)
    anti_analysis = _filter_findings(report.findings, ANOMALY_CATEGORIES)
    ndv_all = _filter_findings(report.findings, NDV_CATEGORIES)
    ndv_capabilities = [item for item in ndv_all if item.category not in DYNAMIC_LOAD_CATEGORIES]
    vulnerabilities = _filter_findings(report.findings, VULNERABILITY_CATEGORIES)

    yara_findings = [
        finding
        for finding in report.findings
        if any(source.tool == "yara" or (source.rule and str(source.rule).startswith("yara:")) for source in finding.sources)
    ]

    string_screening_html = ""
    string_screening_html += "<h3>1.5.1 Detected Endpoints</h3>"
    string_screening_html += _rows_table(["URL", "Examples", "First source"], endpoint_url_rows, "No URLs found.", "endpoints-url", TOP_ENDPOINT_URLS)
    string_screening_html += _rows_table(["IPv4", "Examples", "First source"], endpoint_ip_rows, "No IPv4 addresses found.", "endpoints-ip", TOP_ENDPOINT_IPS)
    string_screening_html += "<h3>1.5.2 Potential Secrets</h3>" + _findings_table(secrets, "secret-findings", 10)
    string_screening_html += "<h3>1.5.3 Dynamic Loading</h3>" + _findings_table(dynamic_load, "dynamic-load-findings", 10)
    string_screening_html += "<h3>1.5.4 Anti-Analysis</h3>" + _findings_table(anti_analysis, "anti-analysis-findings", 10)
    string_screening_html += "<h3>1.5.5 Undeclared Capability Signals</h3>" + _findings_table(ndv_capabilities, "ndv-findings", 12)
    string_screening_html += "<h3>1.5.6 YARA</h3>" + _findings_table(yara_findings, "yara-findings", 10)
    string_screening_html += "<h3>1.5.7 Configuration Vulnerabilities</h3>" + _findings_table(vulnerabilities, "vuln-findings", 15)
    sections.append(_card("s1-string-screening", "1.5 String and Signature Screening", string_screening_html, SECTION_DESCRIPTIONS["string_screening"]))

    native_section = section_by_id.get("native_strings")
    native_payload = native_section.data if native_section else {}
    native_payload = native_payload if isinstance(native_payload, dict) else {}
    native_hits = native_payload.get("top_hits") if isinstance(native_payload.get("top_hits"), list) else []
    native_html = _rows_table(
        ["Field", "Value"],
        [
            [".so files", html.escape(_fmt(native_payload.get("so_files")))],
            ["Hits", html.escape(_fmt(native_payload.get("hits_total")))],
        ],
        "No data.",
        "native-summary",
    )
    native_html += _rows_table(["Top hits"], [[html.escape(hit)] for hit in native_hits], "No matches found.", "native-hits", 10)
    sections.append(_card("s1-native-strings", "1.6 Native .so String Signals", native_html, SECTION_DESCRIPTIONS["native_strings"]))

    findings_summary_html = _severity_summary(report) + _category_top_table(report.findings)
    sections.append(_card("s1-findings-summary", "1.7 Findings Summary", findings_summary_html, "Findings distribution by severity and category."))

    sections.append(_card("s1-artifacts", "1.8 Artifacts", _artifacts_table(report), "Compact list of files and directories generated during analysis."))
    sections.append(_card("s1-notes", "1.9 Notes and Errors", _notes_block(report), "Stage runtime notes and errors."))
    return sections


def _render_stage3(report: ReportV2) -> list[tuple[str, str, str]]:
    sections: list[tuple[str, str, str]] = []
    section_by_id = _section_map(report)

    sections.append(
        _card(
            "s3-identification",
            "3.1 Analysis Target Identification",
            _identification_table(report),
            SECTION_DESCRIPTIONS["identification"],
        )
    )

    sections.append(
        _card(
            "s3-tools",
            "3.2 Tool Status",
            _tools_table(report, limit=8),
            "Execution summary for MobSF, Quark, APKiD, and APKLeaks.",
        )
    )

    mobsf_details = section_by_id.get("mobsf_details")
    mobsf_data = mobsf_details.data if mobsf_details and isinstance(mobsf_details.data, dict) else {}
    score = mobsf_data.get("security_score")
    score_class = "score-medium"
    if isinstance(score, (int, float)):
        if score >= 70:
            score_class = "score-good"
        elif score < 40:
            score_class = "score-bad"
    score_html = f"<div class='score-badge {score_class}'>{html.escape(_fmt(score))}/100</div>" if score is not None else "<p class='muted'>Security score not found.</p>"
    mobsf_high = mobsf_data.get("appsec_high") if isinstance(mobsf_data.get("appsec_high"), list) else []
    mobsf_warning = mobsf_data.get("appsec_warning") if isinstance(mobsf_data.get("appsec_warning"), list) else []
    high_rows = []
    for item in mobsf_high:
        if not isinstance(item, dict):
            continue
        high_rows.append(
            [
                html.escape(_fmt(item.get("title"))),
                html.escape(_fmt(item.get("section"))),
                html.escape(_fmt(item.get("description"))),
            ]
        )
    warning_rows = []
    for item in mobsf_warning:
        if not isinstance(item, dict):
            continue
        warning_rows.append([html.escape(_fmt(item.get("title"))), html.escape(_fmt(item.get("section")))])
    mobsf_urls = mobsf_data.get("urls_top") if isinstance(mobsf_data.get("urls_top"), list) else []
    mobsf_domains = mobsf_data.get("domains_top") if isinstance(mobsf_data.get("domains_top"), list) else []
    mobsf_html = score_html
    mobsf_html += "<h3>High findings</h3>" + _rows_table(["Title", "Section", "Description"], high_rows, "No high findings.", "mobsf-high", 15)
    mobsf_html += "<h3>Warning findings</h3>" + _rows_table(["Title", "Section"], warning_rows, "No warning findings.", "mobsf-warning", 10)
    mobsf_html += "<h3>Top URL</h3>" + _rows_table(["URL"], [[html.escape(str(value))] for value in mobsf_urls], "No URLs found.", "mobsf-urls", 10)
    mobsf_html += "<h3>Top domains</h3>" + _rows_table(["Domain"], [[html.escape(str(value))] for value in mobsf_domains], "No domains found.", "mobsf-domains", 10)
    sections.append(_card("s3-mobsf", "3.3 MobSF Results", mobsf_html, SECTION_DESCRIPTIONS["mobsf"]))

    quark_details = section_by_id.get("quark_details")
    quark_data = quark_details.data if quark_details and isinstance(quark_details.data, dict) else {}
    quark_summary_rows = [
        ["Rules total", html.escape(_fmt(quark_data.get("rules_total")))],
        ["Rules matched", html.escape(_fmt(quark_data.get("rules_matched")))],
        ["Threat level", html.escape(_fmt(quark_data.get("threat_level")))],
        ["Total score", html.escape(_fmt(quark_data.get("total_score")))],
    ]
    crimes = quark_data.get("crimes") if isinstance(quark_data.get("crimes"), list) else []
    crime_rows = []
    for item in crimes:
        if not isinstance(item, dict):
            continue
        crime_rows.append(
            [
                html.escape(_fmt(item.get("rule"))),
                html.escape(_fmt(item.get("crime"))),
                html.escape(_fmt(item.get("score"))),
                html.escape(", ".join(str(label) for label in item.get("label", []) if isinstance(label, str))),
            ]
        )
    quark_html = _rows_table(["Field", "Value"], quark_summary_rows, "No data.", "quark-summary")
    quark_html += _rows_table(["Rule", "Crime", "Score", "Labels"], crime_rows, "No matches.", "quark-crimes", 15)
    sections.append(_card("s3-quark", "3.4 Quark Engine Results", quark_html, SECTION_DESCRIPTIONS["quark"]))

    apkid_details = section_by_id.get("apkid_details")
    apkid_data = apkid_details.data if apkid_details and isinstance(apkid_details.data, dict) else {}
    apkid_rows = []
    for item in apkid_data.get("matches", []) if isinstance(apkid_data.get("matches"), list) else []:
        if not isinstance(item, dict):
            continue
        apkid_rows.append(
            [
                html.escape(_fmt(item.get("file_path"))),
                html.escape(_fmt(item.get("category"))),
                html.escape(_fmt(item.get("value"))),
            ]
        )
    apkid_html = _rows_table(
        ["Filename", "Category", "Value"],
        apkid_rows,
        "No protection mechanisms detected.",
        "apkid-matches",
        30,
    )
    sections.append(_card("s3-apkid", "3.5 APKiD Results", apkid_html, SECTION_DESCRIPTIONS["apkid"]))

    apkleaks_details = section_by_id.get("apkleaks_details")
    apkleaks_data = apkleaks_details.data if apkleaks_details and isinstance(apkleaks_details.data, dict) else {}
    leak_rows = []
    for item in apkleaks_data.get("entries", []) if isinstance(apkleaks_data.get("entries"), list) else []:
        if not isinstance(item, dict):
            continue
        leak_rows.append(
            [
                html.escape(_fmt(item.get("group"))),
                html.escape(_fmt(item.get("value"))),
                html.escape(_fmt(item.get("file_path") or "-")),
            ]
        )
    apkleaks_html = _rows_table(["Type", "Value", "File"], leak_rows, "No leaks detected.", "apkleaks-entries", 20)
    sections.append(_card("s3-apkleaks", "3.6 APKLeaks Results", apkleaks_html, SECTION_DESCRIPTIONS["apkleaks"]))

    indicator_counter = Counter(ind.type for ind in report.indicators)
    indicator_rows = [[html.escape(kind), html.escape(str(count))] for kind, count in sorted(indicator_counter.items())]
    indicators_html = _rows_table(["Kind", "Count"], indicator_rows, "No indicators.", "s3-indicators")
    sections.append(_card("s3-indicators", "3.7 Normalized Indicators", indicators_html, "Aggregated Stage 3 indicators by type."))

    findings_summary_html = _severity_summary(report) + _findings_table(report.findings, "s3-findings", limit=20)
    findings_summary_html += _artifacts_table(report)
    findings_summary_html += _notes_block(report)
    sections.append(_card("s3-summary", "3.8 Findings, Artifacts, and Notes Summary", findings_summary_html, "Final cross-tool stage summary."))
    return sections


def _conf_badge(confidence: str) -> str:
    """Return a colored HTML span for confidence level C1/C2/C3."""
    cls_map = {"C1": "sev-low", "C2": "sev-medium", "C3": "sev-high"}
    label_map = {"C1": "C1 (weak)", "C2": "C2 (indirect)", "C3": "C3 (direct)"}
    c = confidence.upper()
    css = cls_map.get(c, "")
    label = label_map.get(c, html.escape(c))
    return f"<span class='{html.escape(css)}'>{label}</span>" if css else html.escape(confidence)


def _render_stage2_attribution(data: dict) -> str:
    """Render app attribution and exerciser coverage data."""
    attr = data.get("attribution") or {}
    cov = data.get("coverage") or {}
    if not attr and not cov:
        return "<p class='muted'>Attribution data not collected.</p>"

    out = ""
    if attr:
        pid_logcat_empty = attr.get("pid_logcat_empty")
        pid_captured = attr.get("pid_logcat_captured")
        died_at = attr.get("app_died_at") or ""
        rows = [
            ["Package name", html.escape(str(attr.get("package_name") or "-"))],
            ["UID", html.escape(str(attr.get("uid") or "-"))],
            ["PID (initial)", html.escape(str(attr.get("pid_initial") or "-"))],
            ["PID (first seen)", html.escape(str(attr.get("pid_first_seen") or "-"))],
            ["PID (last seen)", html.escape(str(attr.get("pid_last_seen") or "-"))],
            ["App exited early", html.escape("Yes — " + died_at if died_at else "No")],
            [
                "PID-filtered logcat",
                html.escape(
                    "Captured (empty — app produced no output)"
                    if pid_captured and pid_logcat_empty
                    else "Captured"
                    if pid_captured
                    else "Not started (PID unresolved)"
                ),
            ],
        ]
        out += "<h3>Process attribution</h3>"
        out += _rows_table(["Field", "Value"], rows, "No attribution data.", "s2-attr-table")

    if cov:
        sent = cov.get("exerciser_events_sent", 0)
        total = cov.get("exerciser_events_configured", 0)
        pct = cov.get("exerciser_coverage_pct", -1)
        dur = cov.get("capture_duration_sec", 0)
        pct_str = f"{pct}%" if pct >= 0 else "n/a (package unknown)"
        cov_rows = [
            ["Exerciser events sent / configured", html.escape(f"{sent} / {total}")],
            ["Coverage", html.escape(pct_str)],
            ["Capture duration (s)", html.escape(str(dur))],
        ]
        out += "<h3>Exercise coverage</h3>"
        out += _rows_table(["Metric", "Value"], cov_rows, "No coverage data.", "s2-cov-table")

    return out or "<p class='muted'>No attribution data.</p>"


def _render_stage2_findings(data: dict) -> str:
    """Render dynamic analysis findings (§14 validated, FP/TP gated)."""
    findings = data.get("findings") or []
    if not findings:
        return "<p class='muted'>No dynamic findings generated (run may not have completed, or all findings were suppressed).</p>"

    rows = []
    for f in findings:
        fid = html.escape(str(f.get("finding_id", "")))
        conf = _conf_badge(str(f.get("confidence", "")))
        title = html.escape(str(f.get("title", "")))
        detail = html.escape(str(f.get("detail", "")))
        evidence = html.escape(str(f.get("evidence", "") or ""))
        rows.append([f"<span class='mono' style='font-size:0.85em'>{fid}</span>", conf, title, detail, evidence])

    return _rows_table(
        ["Finding ID", "Confidence", "Title", "Detail", "Evidence"],
        rows,
        "No findings.",
        "s2-findings-table",
    )


def _render_stage2_environment(data: dict) -> str:
    env = data.get("environment")
    if not env:
        return "<p class='muted'>Section will be populated when the Stage 2 pipeline is implemented.</p>"
    rows = [
        ["AVD name", html.escape(str(env.get("avd_name", "-")))],
        ["API level", html.escape(str(env.get("api_level", "-")))],
        ["Boot time (s)", html.escape(str(env.get("boot_time_sec", "-")))],
        ["ADB version", html.escape(str(env.get("adb_version", "-")))],
    ]
    return _rows_table(["Parameter", "Value"], rows, "No environment data.", "s2-env-table")


def _render_stage2_install(data: dict) -> str:
    install = data.get("install_diff")
    if not install:
        return "<p class='muted'>Data not collected.</p>"
    new_pkgs = install.get("new_packages") or []
    new_paths = install.get("new_paths") or []
    out = ""
    if new_pkgs:
        rows = [[html.escape(p)] for p in new_pkgs[:50]]
        out += "<h3>New packages</h3>" + _rows_table(["Package"], rows, "None.", "s2-install-pkgs")
    else:
        out += "<p class='muted'>No new packages detected.</p>"
    if new_paths:
        rows2 = [[html.escape(p)] for p in new_paths[:50]]
        out += "<h3>New filesystem paths</h3>" + _rows_table(["Path"], rows2, "None.", "s2-install-paths")
    else:
        out += "<p class='muted'>No new filesystem paths detected.</p>"
    diff_path = install.get("fs_diff_path") or install.get("diff_path") or ""
    if diff_path:
        out += f"<p>Full diff: <span class='mono'>{html.escape(diff_path)}</span></p>"
    return out


def _render_stage2_runtime(data: dict) -> str:
    rt = data.get("runtime_diff")
    if not rt:
        return "<p class='muted'>Data not collected.</p>"
    out = ""

    logcat_path = rt.get("logcat_path") or ""
    pid_logcat_path = rt.get("pid_logcat_path") or ""
    appops_path = rt.get("appops_path") or ""
    pkg_files_count = rt.get("target_pkg_files_count", 0)

    # Logcat paths
    artifact_rows = []
    if logcat_path:
        artifact_rows.append(["Full logcat", f"<span class='mono'>{html.escape(logcat_path)}</span>"])
    if pid_logcat_path:
        artifact_rows.append(["PID-filtered logcat", f"<span class='mono'>{html.escape(pid_logcat_path)}</span>"])
    if appops_path:
        artifact_rows.append(["App ops snapshot", f"<span class='mono'>{html.escape(appops_path)}</span>"])
    if pkg_files_count:
        artifact_rows.append(["Target pkg files captured", html.escape(str(pkg_files_count))])
    if artifact_rows:
        out += "<h3>Captured runtime artifacts</h3>"
        out += _rows_table(["Artifact", "Path"], artifact_rows, "None.", "s2-runtime-artifacts")

    # Filesystem changes
    new_paths = rt.get("new_paths") or []
    if new_paths:
        rows = [[html.escape(p)] for p in new_paths[:50]]
        out += "<h3>Runtime filesystem changes</h3>" + _rows_table(
            ["Path"], rows, "None.", "s2-runtime-paths"
        )
    else:
        out += "<p class='muted'>No new runtime filesystem paths detected.</p>"

    diff_path = rt.get("fs_diff_path") or rt.get("diff_path") or ""
    if diff_path:
        out += f"<p>Full diff: <span class='mono'>{html.escape(diff_path)}</span></p>"

    return out or "<p class='muted'>Data not collected.</p>"


def _render_stage2_network(data: dict) -> str:
    net = data.get("network")
    if not net:
        return "<p class='muted'>Data not collected.</p>"

    rows = [
        ["Unique IPs", html.escape(str(net.get("unique_ips", 0)))],
        ["Unique domains", html.escape(str(net.get("unique_domains", 0)))],
        ["Zeek/tshark analysis", html.escape("Yes" if net.get("zeek_available") else "No (pcap saved)")],
        ["PCAP path", html.escape(str(net.get("pcap_path") or "-"))],
    ]
    out = _rows_table(["Metric", "Value"], rows, "No network data.", "s2-net-summary")

    # Top hosts
    top_hosts = net.get("top_hosts") or []
    if top_hosts:
        host_rows = [[html.escape(h)] for h in top_hosts]
        out += "<h3>Top observed hosts</h3>" + _rows_table(
            ["Host"], host_rows, "None.", "s2-net-hosts"
        )

    # Tshark alert rules triggered
    alerts = net.get("tshark_alerts_summary") or []
    if alerts:
        alert_rows = [
            [
                f"<span class='mono' style='font-size:0.85em'>{html.escape(str(a.get('rule_id', '')))}</span>",
                _conf_badge(str(a.get("confidence", ""))),
                html.escape(str(a.get("title", ""))),
            ]
            for a in alerts
        ]
        out += "<h3>Threat alert rules triggered</h3>"
        out += _rows_table(
            ["Rule ID", "Confidence", "Title"],
            alert_rows,
            "No alerts.",
            "s2-net-alerts",
        )
        alerts_path = net.get("tshark_alerts_path") or ""
        if alerts_path:
            out += f"<p>Full alert detail: <span class='mono'>{html.escape(alerts_path)}</span></p>"
    else:
        out += "<p class='muted'>No tshark threat alert rules triggered.</p>"

    # TSV export files
    tsv_files = net.get("tshark_tsv_files") or {}
    if tsv_files:
        tsv_rows = [
            [html.escape(name), f"<span class='mono'>{html.escape(path)}</span>"]
            for name, path in sorted(tsv_files.items())
            if path and str(path).startswith("/")
        ]
        if tsv_rows:
            out += "<h3>TShark TSV exports</h3>"
            out += _rows_table(["Export name", "Path"], tsv_rows, "None.", "s2-net-tsv")

    # Zeek logs (filter to real file paths)
    captured_files = {
        k: v for k, v in (net.get("zeek_logs") or {}).items()
        if v and str(v).startswith("/")
    }
    if captured_files:
        log_rows = [
            [html.escape(name), f"<span class='mono'>{html.escape(path)}</span>"]
            for name, path in sorted(captured_files.items())
        ]
        out += "<h3>Zeek log files</h3>" + _rows_table(
            ["Log name", "Path"], log_rows, "None.", "s2-net-logs"
        )

    return out


def _render_stage2(report: ReportV2) -> list[tuple[str, str, str]]:
    sections: list[tuple[str, str, str]] = []
    d = report.stage2_data or {}

    # 2.1 — Target identification
    sections.append(
        _card(
            "s2-identification",
            "2.1 Analysis Target Identification",
            _identification_table(report),
            SECTION_DESCRIPTIONS["identification"],
        )
    )

    # 2.2 — App attribution & exercise coverage (new)
    sections.append(_card(
        "s2-attribution", "2.2 App Attribution & Exercise Coverage",
        _render_stage2_attribution(d),
        "Process attribution (UID/PID/logcat), exerciser coverage, and capture duration.",
    ))

    # 2.3 — Emulator environment
    sections.append(_card(
        "s2-environment", "2.3 Runtime Environment",
        _render_stage2_environment(d),
        "Emulator, ADB, and network environment parameters.",
    ))

    # 2.4 — Tool status
    sections.append(_card("s2-tools", "2.4 Tool Status", _tools_table(report), "Dynamic analysis tool status."))

    # 2.5 — Install changes
    sections.append(_card(
        "s2-install", "2.5 Installation Changes",
        _render_stage2_install(d),
        SECTION_DESCRIPTIONS["install_changes"],
    ))

    # 2.6 — Runtime behavior
    sections.append(_card(
        "s2-runtime", "2.6 Runtime Behavior",
        _render_stage2_runtime(d),
        SECTION_DESCRIPTIONS["runtime_behavior"],
    ))

    # 2.7 — Network activity (with tshark alerts)
    sections.append(_card(
        "s2-network", "2.7 Network Activity",
        _render_stage2_network(d),
        SECTION_DESCRIPTIONS["network_activity"],
    ))

    # 2.8 — Dynamic analysis findings (§14 validated, FP/TP gated)
    sections.append(_card(
        "s2-findings", "2.8 Dynamic Analysis Findings",
        _render_stage2_findings(d),
        "FP/TP validated dynamic findings. Confidence: C1=weak indicator, C2=strong indirect, C3=direct proof.",
    ))

    # 2.9 — Stage 1 correlation
    correlation_html = (
        "<p class='muted'>Correlation with Stage 1 to be implemented.</p>"
        if not d.get("correlation")
        else "<p>Correlation data collected. Manual expert review required.</p>"
    )
    sections.append(_card(
        "s2-correlation", "2.9 Stage 1 Correlation",
        correlation_html,
        "Correlation between static and dynamic indicators.",
    ))

    # 2.10 — Summary
    summary_html = _severity_summary(report) + _artifacts_table(report) + _notes_block(report)
    sections.append(_card(
        "s2-summary", "2.10 Artifacts & Notes Summary",
        summary_html,
        "Dynamic stage artifacts and error notes.",
    ))
    return sections


def _render_overall(report: ReportV2) -> list[tuple[str, str, str]]:
    sections: list[tuple[str, str, str]] = []
    sections.append(
        _card(
            "o-identification",
            "O.1 Target Identification",
            _identification_table(report),
            SECTION_DESCRIPTIONS["identification"],
        )
    )

    sections.append(_card("o-tools", "O.2 Tools Used", _tools_table(report, limit=20), "Tools used across all stages."))

    dedup: dict[str, FindingV2] = {}
    for finding in report.findings:
        key = f"{finding.category}|{_finding_evidence_snippet(finding)}"
        if key not in dedup:
            dedup[key] = finding
    unique_findings = list(dedup.values())

    overall_html = _severity_summary(report) + _findings_table(unique_findings, "overall-top-findings", 20)
    sections.append(_card("o-findings", "O.3 Aggregated Findings Summary", overall_html, "Deduplicated findings by category+evidence."))

    ndv_findings = _filter_findings(unique_findings, NDV_CATEGORIES)
    sections.append(_card("o-ndv", "O.4 Undeclared Capability Signals", _findings_table(ndv_findings, "overall-ndv", 15), "Potential undeclared capability categories."))

    vulnerabilities = _filter_findings(unique_findings, VULNERABILITY_CATEGORIES)
    sections.append(_card("o-vuln", "O.5 Detected Vulnerabilities", _findings_table(vulnerabilities, "overall-vuln", 20), SECTION_DESCRIPTIONS["vulnerabilities"]))

    secrets = _filter_findings(unique_findings, SECRET_CATEGORIES)
    sections.append(_card("o-secrets", "O.6 Detected Secrets", _findings_table(secrets, "overall-secrets", 20), SECTION_DESCRIPTIONS["secrets"]))

    signing = _filter_findings(unique_findings, SIGNING_CATEGORIES)
    sections.append(_card("o-supply-chain", "O.7 Supply Chain", _findings_table(signing, "overall-signing", 15), "Signature and certificate issues."))

    high_count = sum(1 for finding in unique_findings if finding.severity == "high")
    medium_findings = [finding for finding in unique_findings if finding.severity == "medium"]
    verdict = "Indicators requiring further analysis were detected."
    reason = "High/medium findings require expert validation."
    if high_count == 0 and len(medium_findings) <= 3 and all(item.confidence == "C1" for item in medium_findings):
        verdict = "No indicators requiring further analysis were detected."
        reason = "No high findings; medium findings are within threshold and confidence C1."
    verdict_html = f"<p><strong>{html.escape(verdict)}</strong></p><p class='muted'>{html.escape(reason)}</p>"
    sections.append(_card("o-verdict", "O.8 Final Assessment", verdict_html, SECTION_DESCRIPTIONS["overall_verdict"]))

    summary_html = _artifacts_table(report) + _notes_block(report)
    sections.append(_card("o-artifacts", "O.9 Artifacts and Notes", summary_html, "Links to final artifacts and operational notes."))
    return sections


def _render_header(report: ReportV2) -> str:
    logo = _logo_data_uri()
    logo_html = f"<img class='brand-logo' src='{logo}' alt='{APP_NAME} logo'/>" if logo else ""
    title = REPORT_TITLES.get(report.stage, "TAPKA report")
    return (
        "<header class='report-brand'>"
        f"{logo_html}"
        "<div>"
        f"<div class='brand-name'>{html.escape(APP_NAME)}</div>"
        f"<div class='brand-tagline'>{html.escape(title)}</div>"
        f"<p class='muted brand-desc'>Schema: {html.escape(report.schema_version)} | Stage: {html.escape(report.stage)}</p>"
        "</div>"
        "<div class='header-actions'>"
        "<button class='btn-link' onclick='window.print()'>Print / Export PDF</button>"
        "</div>"
        "</header>"
    )


def _render_toc(cards: list[tuple[str, str, str]]) -> str:
    items = "".join(
        f"<li><a href='#{html.escape(section_id)}'>{html.escape(title)}</a></li>" for section_id, title, _ in cards
    )
    return f"<section class='card'><h2>Contents</h2><ul class='toc'>{items}</ul></section>"


def _render_document(report: ReportV2, cards: list[tuple[str, str, str]]) -> str:
    body = "".join(card_html for _, _, card_html in cards)
    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>{html.escape(APP_NAME)} Report</title>
  <style>
    body {{ margin: 0; font-family: "IBM Plex Sans", "Noto Sans", sans-serif; background: #121417; color: #e6e9ee; }}
    .container {{ padding: 24px; max-width: 1280px; margin: 0 auto; }}
    .report-brand {{ display: flex; gap: 16px; align-items: center; margin-bottom: 18px; padding-bottom: 12px; border-bottom: 1px solid #2b3138; }}
    .brand-logo {{ width: 56px; height: 56px; border-radius: 12px; object-fit: contain; background: #1b1f24; border: 1px solid #2b3138; padding: 6px; }}
    .brand-name {{ font-size: 22px; font-weight: 700; letter-spacing: 0.2px; }}
    .brand-tagline {{ font-size: 13px; color: #9aa3ad; text-transform: uppercase; letter-spacing: 0.12em; }}
    .brand-desc {{ margin: 6px 0 0 0; }}
    .header-actions {{ margin-left: auto; }}
    .card {{ background: #1b1f24; border: 1px solid #2b3138; border-radius: 12px; padding: 16px; margin-bottom: 16px; }}
    .muted {{ color: #9aa3ad; }}
    .mono {{ font-family: "IBM Plex Mono", "Menlo", monospace; overflow-wrap: anywhere; word-break: break-word; }}
    .section-desc {{ margin-top: -6px; margin-bottom: 12px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 8px; table-layout: fixed; }}
    th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #2b3138; vertical-align: top; min-width: 0; overflow-wrap: anywhere; word-break: break-word; }}
    th {{ font-size: 12px; text-transform: uppercase; color: #9aa3ad; }}
    .toc {{ margin: 0; padding-left: 18px; }}
    .toc a {{ color: #a8c7fa; text-decoration: none; }}
    .toc a:hover {{ text-decoration: underline; }}
    .btn-link {{ background: transparent; color: #a8c7fa; border: 1px solid #2b3138; padding: 6px 10px; border-radius: 8px; cursor: pointer; }}
    .btn-mini {{ background: transparent; color: #a8c7fa; border: 1px solid #2b3138; padding: 2px 8px; border-radius: 8px; cursor: pointer; font-size: 12px; }}
    .status-ok {{ color: #4db7b0; }}
    .status-partial {{ color: #f5a65b; }}
    .status-fail {{ color: #ff7b7b; }}
    .status-skipped {{ color: #9aa3ad; }}
    .sev-high {{ color: #ff7b7b; font-weight: 600; }}
    .sev-medium {{ color: #f5a65b; font-weight: 600; }}
    .sev-low {{ color: #a8c7fa; font-weight: 600; }}
    .sev-info {{ color: #9aa3ad; font-weight: 600; }}
    .score-badge {{ display: inline-block; padding: 10px 14px; border-radius: 10px; font-size: 22px; font-weight: 700; border: 1px solid #2b3138; margin: 6px 0 12px 0; }}
    .score-good {{ background: rgba(77, 183, 176, 0.2); color: #4db7b0; }}
    .score-medium {{ background: rgba(245, 166, 91, 0.2); color: #f5a65b; }}
    .score-bad {{ background: rgba(255, 123, 123, 0.2); color: #ff7b7b; }}
    .hidden {{ display: none; }}
    ul {{ margin: 0; padding-left: 20px; }}

    @media print {{
      body {{ background: #fff; color: #000; }}
      .card {{ border-color: #aaa; background: #fff; page-break-inside: avoid; }}
      .btn-link, .btn-mini {{ display: none !important; }}
      a {{ color: #000; text-decoration: none; }}
    }}
  </style>
  <script>
    function tapkaToggle(id, btn) {{
      const node = document.getElementById(id);
      if (!node) return;
      const hidden = node.classList.toggle('hidden');
      if (btn) btn.textContent = hidden ? 'Show all' : 'Collapse';
    }}
    function tapkaCopy(value) {{
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(value || '');
    }}
  </script>
</head>
<body>
  <div class="container">
    {_render_header(report)}
    {_render_toc(cards)}
    {body}
  </div>
</body>
</html>
"""


def render_report_html(report: ReportV2) -> str:
    if report.stage == STAGE_STATIC:
        cards = _render_stage1(report)
    elif report.stage == STAGE_CROSS_TOOL:
        cards = _render_stage3(report)
    elif report.stage == STAGE_DYNAMIC:
        cards = _render_stage2(report)
    elif report.stage == STAGE_OVERALL:
        cards = _render_overall(report)
    else:
        generic = _card(
            "generic",
            "Report",
            _identification_table(report) + _tools_table(report) + _findings_table(report.findings, "generic-findings") + _artifacts_table(report),
            None,
        )
        cards = [generic]
    return _render_document(report, cards)
