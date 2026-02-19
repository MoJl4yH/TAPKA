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
    "identification": "Идентификационные сведения об анализируемом APK для обеспечения воспроизводимости результатов.",
    "signing": "Анализ цифровой подписи APK: применяемые схемы, идентификация подписанта, криптографические характеристики.",
    "manifest": "Метаданные и декларации приложения: разрешения, экспортируемые компоненты, конфигурационные флаги.",
    "string_screening": "Поверхностный строковый и сигнатурный скрининг декодированного содержимого APK.",
    "endpoints": "Обнаруженные обращения к внешним ресурсам (URL, IPv4) в коде и ресурсах приложения.",
    "secrets": "Потенциально захардкоженные чувствительные данные: ключи, токены, пароли, JWT.",
    "dynamic_load": "Индикаторы динамической загрузки кода и выполнения команд ОС.",
    "anti_analysis": "Индикаторы защиты от анализа: проверки эмулятора, root, Frida, отладчика.",
    "ndv_capabilities": "Потенциально опасные возможности: удалённое управление, перехват, слежка.",
    "yara_screening": "Результаты сигнатурного скрининга по правилам YARA.",
    "vulnerabilities": "Уязвимости конфигурации и небезопасные паттерны реализации.",
    "native_strings": "Строки, извлечённые из нативных библиотек (.so) и проверенные на индикаторы.",
    "network_activity": "Фактические сетевые соединения приложения, зафиксированные при динамическом анализе.",
    "install_changes": "Изменения файловой системы и состояния системы после установки APK.",
    "runtime_behavior": "Поведение приложения при выполнении: сервисы, receivers, ошибки.",
    "mobsf": "Результаты комплексного анализа MobSF: security score, уязвимости, конфигурации.",
    "quark": "Результаты поведенческого анализа Quark Engine: сработавшие правила.",
    "apkid": "Идентификация упаковщиков, обфускаторов и защитных механизмов (APKiD).",
    "apkleaks": "Потенциальные утечки чувствительных данных и конфигураций (APKLeaks).",
    "overall_verdict": "Итоговая оценка по двухуровневой шкале методики.",
}

REPORT_TITLES = {
    STAGE_STATIC: "Отчёт статического экспертно-инструментального анализа (Этап 1)",
    STAGE_DYNAMIC: "Отчёт динамического экспертно-инструментального анализа (Этап 2)",
    STAGE_CROSS_TOOL: "Отчёт кросс-инструментального анализа (Этап 3)",
    STAGE_OVERALL: "Итоговое экспертное заключение по результатам анализа Android-приложения",
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
            f"Показать все ({len(rows)})</button>"
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
        "Артефакты отсутствуют.",
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
    return _rows_table(["Tool", "Status", "Duration ms", "Metrics"], rows, "Инструменты не зафиксированы.", "tools", limit)


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
    return _rows_table(["Severity", "Count"], rows, "Нет findings.", "severity-summary")


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
    return _rows_table(["Category", "Max severity", "Count", "Examples"], rows, "Нет данных по категориям.", "category-top", limit)


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
    return _rows_table(["Severity", "Category", "Title", "Location", "Evidence"], rows, "Нет findings.", table_id, limit)


def _notes_block(report: ReportV2) -> str:
    if not report.notes:
        return "<p class='muted'>Примечания отсутствуют.</p>"
    rows = "".join(f"<li>{html.escape(note)}</li>" for note in report.notes)
    return f"<ul>{rows}</ul>"


def _render_stage1(report: ReportV2) -> list[tuple[str, str, str]]:
    sections: list[tuple[str, str, str]] = []
    section_by_id = _section_map(report)

    sections.append(
        _card(
            "s1-identification",
            "1.1 Идентификация объекта анализа",
            _identification_table(report),
            SECTION_DESCRIPTIONS["identification"],
        )
    )

    sections.append(
        _card(
            "s1-tools",
            "1.2 Статус инструментов",
            _tools_table(report),
            "Состояние запусков инструментов и их ключевые метрики по этапу статического анализа.",
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
    signing_html += "<h3>Схемы подписи</h3>" + _rows_table(["Scheme", "Enabled"], scheme_rows, "Нет данных.", "sign-schemes")
    signing_html += "<h3>Сертификат</h3>" + _rows_table(["Field", "Value"], cert_rows, "Нет данных.", "sign-cert")
    signing_html += "<h3>Проблемы подписи</h3>" + _findings_table(signing_findings, "sign-findings", limit=10)
    sections.append(_card("s1-signing", "1.3 Анализ подписи APK", signing_html, SECTION_DESCRIPTIONS["signing"]))

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
        "Нет данных.",
        "manifest-summary",
    )
    manifest_html += "<h3>Флаги</h3>" + _rows_table(["Flag"], [[html.escape(item)] for item in flags], "Нет флагов.", "manifest-flags", 15)
    manifest_html += "<h3>Разрешения</h3>" + _rows_table(
        ["Permission"], [[f"<span class='mono'>{html.escape(item)}</span>"] for item in permissions], "Нет разрешений.", "manifest-perm", 20
    )
    manifest_html += "<h3>Экспортируемые компоненты</h3>" + _rows_table(
        ["Component"], [[f"<span class='mono'>{html.escape(item)}</span>"] for item in exported], "Нет экспортируемых компонентов.", "manifest-exp", 15
    )
    sections.append(_card("s1-manifest", "1.4 Манифест и конфигурация", manifest_html, SECTION_DESCRIPTIONS["manifest"]))

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
    string_screening_html += "<h3>1.5.1 Обнаруженные endpoints</h3>"
    string_screening_html += _rows_table(["URL", "Examples", "First source"], endpoint_url_rows, "URL не обнаружены.", "endpoints-url", TOP_ENDPOINT_URLS)
    string_screening_html += _rows_table(["IPv4", "Examples", "First source"], endpoint_ip_rows, "IPv4 не обнаружены.", "endpoints-ip", TOP_ENDPOINT_IPS)
    string_screening_html += "<h3>1.5.2 Потенциальные секреты</h3>" + _findings_table(secrets, "secret-findings", 10)
    string_screening_html += "<h3>1.5.3 Динамическая загрузка</h3>" + _findings_table(dynamic_load, "dynamic-load-findings", 10)
    string_screening_html += "<h3>1.5.4 Антианализ</h3>" + _findings_table(anti_analysis, "anti-analysis-findings", 10)
    string_screening_html += "<h3>1.5.5 Признаки НДВ</h3>" + _findings_table(ndv_capabilities, "ndv-findings", 12)
    string_screening_html += "<h3>1.5.6 YARA</h3>" + _findings_table(yara_findings, "yara-findings", 10)
    string_screening_html += "<h3>1.5.7 Уязвимости конфигурации</h3>" + _findings_table(vulnerabilities, "vuln-findings", 15)
    sections.append(_card("s1-string-screening", "1.5 Строковый и сигнатурный скрининг", string_screening_html, SECTION_DESCRIPTIONS["string_screening"]))

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
        "Нет данных.",
        "native-summary",
    )
    native_html += _rows_table(["Top hits"], [[html.escape(hit)] for hit in native_hits], "Совпадений не найдено.", "native-hits", 10)
    sections.append(_card("s1-native-strings", "1.6 Строки из .so библиотек", native_html, SECTION_DESCRIPTIONS["native_strings"]))

    findings_summary_html = _severity_summary(report) + _category_top_table(report.findings)
    sections.append(_card("s1-findings-summary", "1.7 Сводка findings", findings_summary_html, "Распределение findings по severity и категориям."))

    sections.append(_card("s1-artifacts", "1.8 Артефакты", _artifacts_table(report), "Компактный перечень файлов и директорий, сформированных при анализе."))
    sections.append(_card("s1-notes", "1.9 Примечания и ошибки", _notes_block(report), "Служебные сообщения и ошибки этапа."))
    return sections


def _render_stage3(report: ReportV2) -> list[tuple[str, str, str]]:
    sections: list[tuple[str, str, str]] = []
    section_by_id = _section_map(report)

    sections.append(
        _card(
            "s3-identification",
            "3.1 Идентификация объекта анализа",
            _identification_table(report),
            SECTION_DESCRIPTIONS["identification"],
        )
    )

    sections.append(
        _card(
            "s3-tools",
            "3.2 Статус инструментов",
            _tools_table(report, limit=8),
            "Сводка запусков MobSF, Quark, APKiD и APKLeaks.",
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
    score_html = f"<div class='score-badge {score_class}'>{html.escape(_fmt(score))}/100</div>" if score is not None else "<p class='muted'>Security score не найден.</p>"
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
    mobsf_html += "<h3>High findings</h3>" + _rows_table(["Title", "Section", "Description"], high_rows, "Нет high findings.", "mobsf-high", 15)
    mobsf_html += "<h3>Warning findings</h3>" + _rows_table(["Title", "Section"], warning_rows, "Нет warning findings.", "mobsf-warning", 10)
    mobsf_html += "<h3>Top URL</h3>" + _rows_table(["URL"], [[html.escape(str(value))] for value in mobsf_urls], "URL отсутствуют.", "mobsf-urls", 10)
    mobsf_html += "<h3>Top domains</h3>" + _rows_table(["Domain"], [[html.escape(str(value))] for value in mobsf_domains], "Домены отсутствуют.", "mobsf-domains", 10)
    sections.append(_card("s3-mobsf", "3.3 Результаты MobSF", mobsf_html, SECTION_DESCRIPTIONS["mobsf"]))

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
    quark_html = _rows_table(["Field", "Value"], quark_summary_rows, "Нет данных.", "quark-summary")
    quark_html += _rows_table(["Rule", "Crime", "Score", "Labels"], crime_rows, "Срабатываний нет.", "quark-crimes", 15)
    sections.append(_card("s3-quark", "3.4 Результаты Quark Engine", quark_html, SECTION_DESCRIPTIONS["quark"]))

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
        "Защитные механизмы не выявлены.",
        "apkid-matches",
        30,
    )
    sections.append(_card("s3-apkid", "3.5 Результаты APKiD", apkid_html, SECTION_DESCRIPTIONS["apkid"]))

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
    apkleaks_html = _rows_table(["Type", "Value", "File"], leak_rows, "Утечки не обнаружены.", "apkleaks-entries", 20)
    sections.append(_card("s3-apkleaks", "3.6 Результаты APKLeaks", apkleaks_html, SECTION_DESCRIPTIONS["apkleaks"]))

    indicator_counter = Counter(ind.type for ind in report.indicators)
    indicator_rows = [[html.escape(kind), html.escape(str(count))] for kind, count in sorted(indicator_counter.items())]
    indicators_html = _rows_table(["Kind", "Count"], indicator_rows, "Индикаторы отсутствуют.", "s3-indicators")
    sections.append(_card("s3-indicators", "3.7 Нормализованные индикаторы", indicators_html, "Агрегированные индикаторы Stage3 по типам."))

    findings_summary_html = _severity_summary(report) + _findings_table(report.findings, "s3-findings", limit=20)
    findings_summary_html += _artifacts_table(report)
    findings_summary_html += _notes_block(report)
    sections.append(_card("s3-summary", "3.8 Сводка findings, артефакты, примечания", findings_summary_html, "Итоговые результаты кросс-инструментального этапа."))
    return sections


def _render_stage2(report: ReportV2) -> list[tuple[str, str, str]]:
    sections: list[tuple[str, str, str]] = []
    sections.append(
        _card(
            "s2-identification",
            "2.1 Идентификация объекта анализа",
            _identification_table(report),
            SECTION_DESCRIPTIONS["identification"],
        )
    )
    sections.append(_card("s2-environment", "2.2 Параметры среды", "<p class='muted'>Секция готова к заполнению после реализации Stage2 pipeline.</p>", "Параметры эмулятора, ADB и сетевого окружения."))
    sections.append(_card("s2-tools", "2.3 Статус инструментов", _tools_table(report), "Состояние инструментов динамического анализа."))
    sections.append(_card("s2-install", "2.4 Изменения при установке", "<p class='muted'>Данные не собраны.</p>", SECTION_DESCRIPTIONS["install_changes"]))
    sections.append(_card("s2-runtime", "2.5 Поведение при выполнении", "<p class='muted'>Данные не собраны.</p>", SECTION_DESCRIPTIONS["runtime_behavior"]))
    sections.append(_card("s2-network", "2.6 Сетевая активность", "<p class='muted'>Данные не собраны.</p>", SECTION_DESCRIPTIONS["network_activity"]))
    sections.append(_card("s2-correlation", "2.7 Сопоставление со Stage1", "<p class='muted'>Данные не собраны.</p>", "Корреляция статических и динамических индикаторов."))
    summary_html = _severity_summary(report) + _artifacts_table(report) + _notes_block(report)
    sections.append(_card("s2-summary", "2.8 Сводка findings, артефакты, примечания", summary_html, "Итоги динамического этапа."))
    return sections


def _render_overall(report: ReportV2) -> list[tuple[str, str, str]]:
    sections: list[tuple[str, str, str]] = []
    sections.append(
        _card(
            "o-identification",
            "O.1 Идентификация объекта",
            _identification_table(report),
            SECTION_DESCRIPTIONS["identification"],
        )
    )

    sections.append(_card("o-tools", "O.2 Используемый инструментарий", _tools_table(report, limit=20), "Инструменты, использованные во всех этапах."))

    dedup: dict[str, FindingV2] = {}
    for finding in report.findings:
        key = f"{finding.category}|{_finding_evidence_snippet(finding)}"
        if key not in dedup:
            dedup[key] = finding
    unique_findings = list(dedup.values())

    overall_html = _severity_summary(report) + _findings_table(unique_findings, "overall-top-findings", 20)
    sections.append(_card("o-findings", "O.3 Агрегированная сводка findings", overall_html, "Дедуплицированные findings по category+evidence."))

    ndv_findings = _filter_findings(unique_findings, NDV_CATEGORIES)
    sections.append(_card("o-ndv", "O.4 Выявленные признаки НДВ", _findings_table(ndv_findings, "overall-ndv", 15), "Категории потенциальных недекларированных возможностей."))

    vulnerabilities = _filter_findings(unique_findings, VULNERABILITY_CATEGORIES)
    sections.append(_card("o-vuln", "O.5 Выявленные уязвимости", _findings_table(vulnerabilities, "overall-vuln", 20), SECTION_DESCRIPTIONS["vulnerabilities"]))

    secrets = _filter_findings(unique_findings, SECRET_CATEGORIES)
    sections.append(_card("o-secrets", "O.6 Выявленные секреты", _findings_table(secrets, "overall-secrets", 20), SECTION_DESCRIPTIONS["secrets"]))

    signing = _filter_findings(unique_findings, SIGNING_CATEGORIES)
    sections.append(_card("o-supply-chain", "O.7 Цепочка поставок", _findings_table(signing, "overall-signing", 15), "Проблемы подписи и сертификатов."))

    high_count = sum(1 for finding in unique_findings if finding.severity == "high")
    medium_findings = [finding for finding in unique_findings if finding.severity == "medium"]
    verdict = "Выявлены признаки, требующие дополнительного анализа"
    reason = "Найдены high/medium findings, требующие экспертной валидации."
    if high_count == 0 and len(medium_findings) <= 3 and all(item.confidence == "C1" for item in medium_findings):
        verdict = "Признаки, требующие дополнительного анализа, не выявлены"
        reason = "High findings отсутствуют, medium findings в пределах порога и с confidence C1."
    verdict_html = f"<p><strong>{html.escape(verdict)}</strong></p><p class='muted'>{html.escape(reason)}</p>"
    sections.append(_card("o-verdict", "O.8 Итоговая оценка", verdict_html, SECTION_DESCRIPTIONS["overall_verdict"]))

    summary_html = _artifacts_table(report) + _notes_block(report)
    sections.append(_card("o-artifacts", "O.9 Артефакты и примечания", summary_html, "Ссылки на итоговые артефакты и служебные заметки."))
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
        "<button class='btn-link' onclick='window.print()'>Печать / Export PDF</button>"
        "</div>"
        "</header>"
    )


def _render_toc(cards: list[tuple[str, str, str]]) -> str:
    items = "".join(
        f"<li><a href='#{html.escape(section_id)}'>{html.escape(title)}</a></li>" for section_id, title, _ in cards
    )
    return f"<section class='card'><h2>Содержание</h2><ul class='toc'>{items}</ul></section>"


def _render_document(report: ReportV2, cards: list[tuple[str, str, str]]) -> str:
    body = "".join(card_html for _, _, card_html in cards)
    return f"""
<!doctype html>
<html lang="ru">
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
      if (btn) btn.textContent = hidden ? 'Показать все' : 'Свернуть';
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
