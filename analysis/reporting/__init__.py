from __future__ import annotations

import hashlib
import json
import mimetypes
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from analysis.runtime.clock import now_utc_iso
from analysis.runtime.hash import sha256_file
from analysis.localization import translate_category
from analysis.reporting.stage3_html_report import render_report_html
from analysis.severity import SeverityEngine
from analysis.stages import STAGE_CROSS_TOOL, STAGE_DYNAMIC, STAGE_OVERALL, STAGE_STATIC
from analysis.storage import Storage
from models import Finding, Project, Run
from models.report_v2 import (
    ArtifactRefV2,
    EvidenceItemV2,
    FindingV2,
    IndicatorExampleV2,
    IndicatorV2,
    ProjectInfoV2,
    ReportStatusV2,
    ReportV2,
    RunInfoV2,
    SectionV2,
    SeverityHintV2,
    SourceRefV2,
    ToolRunV2,
    ToolStatusV2,
)

REPORT_FILENAMES = {
    STAGE_STATIC: ("stage1_report.json", "stage1_report.html"),
    STAGE_DYNAMIC: ("stage2_report.json", "stage2_report.html"),
    STAGE_CROSS_TOOL: ("stage3_report.json", "stage3_report.html"),
    STAGE_OVERALL: ("overall_report.json", "overall_report.html"),
}

CATEGORY_DESCRIPTIONS = {
    "ndv_remote_command": "Каналы удалённого управления могут обеспечивать удалённую оркестрацию или доставку полезной нагрузки.",
    "ndv_traffic_intercept_vpn": "Индикаторы VPN/TUN могут указывать на перехват или мониторинг трафика.",
    "ndv_screen_capture_mediaprojection": "Использование MediaProjection позволяет захватывать экран или отдельные кадры.",
    "ndv_accessibility_surveillance": "API Accessibility позволяют наблюдать содержимое UI и действия пользователя.",
    "ndv_keylogging_like": "Текстовые события Accessibility могут имитировать поведение кейлоггера.",
    "ndv_mic_eavesdropping": "Audio API с разрешением RECORD_AUDIO указывают на доступ к микрофону.",
    "ndv_camera_surveillance": "Camera API в сочетании с разрешениями свидетельствуют об использовании камеры.",
    "ndv_geo_tracking_background": "Фоновое геоотслеживание может происходить постоянно.",
    "ndv_geo_tracking_foreground": "Доступ к геолокации в активном режиме позволяет отслеживать положение пользователя.",
    "ndv_clipboard_monitoring": "API буфера обмена позволяют захватывать скопированные данные.",
    "ndv_sms_intercept": "Разрешения SMS могут открывать доступ к перехвату сообщений.",
    "ndv_notification_listener": "Доступ через NotificationListener позволяет читать уведомления пользователя.",
    "ndv_overlay_abuse": "Возможности оверлея могут использоваться для UI-фишинга.",
    "sec_tls_trust_all": "Паттерны принятия всех TLS-сертификатов ослабляют безопасность транспорта.",
    "sec_hostname_verifier_bypass": "Обход проверки имени хоста создаёт риски MITM-атак.",
    "sec_cleartext_traffic_allowed": "Разрешение незашифрованного трафика снижает защиту транспортного уровня.",
    "sec_insecure_webview_bridge": "JS-мосты WebView увеличивают поверхность атаки.",
    "sec_insecure_webview_file_access": "Файловый доступ WebView может раскрывать локальные файлы.",
    "sec_custom_ca_store_or_user_certs": "Нестандартное хранилище доверия может ослаблять проверку TLS.",
    "sec_proxy_setting_modification": "Изменение настроек прокси может перенаправлять трафик.",
    "vul_exported_component_no_permission": "Экспортируемые компоненты без разрешений несут риски безопасности.",
    "vul_exported_provider_risky": "Экспортируемые провайдеры могут раскрывать или утечь данные.",
    "vul_fileprovider_misconfig": "Ошибочная конфигурация FileProvider может открывать доступ к файлам.",
    "vul_pendingintent_mutable": "Изменяемый PendingIntent может быть перехвачен другими приложениями.",
    "vul_deeplink_intent_injection": "Deeplink-интенты могут допускать инъекцию данных из внешних источников.",
    "vul_backup_enabled": "Резервные копии могут раскрывать данные приложения при недостаточной защите.",
    "vul_debuggable_true": "Отладочные сборки несут высокий риск в производственной среде.",
    "ndv_dynamic_code_loading_dex": "Динамическая загрузка DEX-классов позволяет выполнять инъекцию кода в runtime.",
    "ndv_remote_command_shell": "Выполнение shell-команд через Runtime.exec или ProcessBuilder.",
    "ndv_payload_decode_load": "Декодирование Base64 в сочетании с загрузкой DEX указывает на зашифрованную полезную нагрузку.",
    "ndv_native_code_loader_suspicious": "Загрузка нативного кода может скрывать функциональность.",
    "ndv_reflection_heavy": "Интенсивное использование рефлексии указывает на обфускацию или динамическое поведение.",
    "ndv_download_execute": "Паттерны «скачать и выполнить» несут высокий риск.",
    "secret_private_key_pem": "Встроенные приватные ключи открывают возможность компрометации учётных данных.",
    "secret_hardcoded_token_or_apikey": "Жёстко заданные токены или API-ключи раскрывают секреты.",
    "secret_jwt_embedded": "Встроенные JWT могут утечь данные аутентификации.",
    "secret_password_like": "Строки, похожие на пароли, указывают на жёстко заданные учётные данные.",
    "secret_endpoints_hardcoded": "Жёстко заданные конечные точки раскрывают внутреннюю инфраструктуру.",
    "persist_boot_completed": "BOOT_COMPLETED-приёмники указывают на механизмы закрепления.",
    "persist_workmanager_periodic": "Периодические задачи WorkManager указывают на закрепление.",
    "persist_jobscheduler_periodic": "Периодические задачи JobScheduler указывают на закрепление.",
    "persist_alarmmanager_repeating": "Повторяющиеся AlarmManager-события указывают на закрепление.",
    "anomaly_root_detection": "Проверки root указывают на антианализ.",
    "anomaly_frida_xposed_magisk_detection": "Обнаружение Frida/Xposed указывает на противодействие модификации.",
    "anomaly_emulator_detection": "Проверки эмулятора указывают на тактики уклонения.",
    "anomaly_obfuscation_heavy": "Сильная обфускация может скрывать назначение кода.",
    "anomaly_anti_debug": "Логика противодействия отладке затрудняет анализ.",
    "anomaly_anti_tamper": "Проверки целостности выявляют модификацию APK.",
    "anomaly_proxy_evasion": "Обход прокси препятствует анализу трафика.",
    "ndv_sms_send": "Возможность отправки SMS может указывать на мошенническое поведение.",
    "ndv_device_admin": "Device Admin API обеспечивает управление политиками на уровне устройства.",
    "ndv_device_identifiers": "Доступ к идентификаторам устройства может использоваться для слежения за пользователем.",
    "ndv_contacts_access": "Доступ к контактам/журналу вызовов/календарю раскрывает персональные данные.",
    "ndv_account_enumeration": "Перечисление учётных записей раскрывает подключённые сервисы пользователя.",
    "ndv_wifi_fingerprinting": "Результаты Wi-Fi-сканирования могут использоваться для геолокации пользователя.",
    "ndv_bluetooth_enumeration": "Перечисление Bluetooth-устройств раскрывает сопряжённые устройства.",
    "ndv_app_enumeration": "Перечисление установленных приложений позволяет профилировать поведение пользователя.",
    "ndv_proxy_bypass": "Обход прокси препятствует инспекции трафика.",
    "sec_weak_crypto": "Слабые криптографические алгоритмы (ECB/DES/RC4/MD5) подрывают защиту данных.",
    "sec_predictable_random": "Предсказуемый seed SecureRandom компрометирует криптографические операции.",
    "sec_world_readable_writable": "Файлы с глобальными правами чтения/записи открыты для других приложений.",
    "sec_external_storage_sensitive": "Внешнее хранилище доступно всем приложениям с разрешением на хранилище.",
    "sec_webview_js_eval": "Выполнение JavaScript в WebView может открывать возможность XSS-атак.",
    "sec_sql_injection": "Конкатенация строк в SQL-запросах создаёт риск SQL-инъекции.",
    "sec_log_sensitive_data": "Чувствительные данные в журналах доступны через logcat.",
    "sec_sharedprefs_sensitive": "Чувствительные данные в SharedPreferences хранятся в открытом XML.",
    "sec_intent_extra_no_validation": "Intent extras без валидации могут допускать инъекцию данных.",
    "sec_network_security_config_weak": "Слабая конфигурация сетевой безопасности допускает незашифрованный трафик или недоверенные CA.",
    "sec_certificate_pinning": "Certificate pinning присутствует — учитывать при динамическом анализе.",
    "sec_cleartext_http_endpoint": "HTTP-конечная точка без шифрования позволяет перехватывать трафик и похищать учётные данные (CWE-319).",
    "secret_hardcoded_credentials": "Жёстко заданные учётные данные в исходном коде приложения (CWE-798).",
    "sec_broadcast_receiver_no_permission": "Динамически зарегистрированный BroadcastReceiver без аргумента permission (CWE-925).",
    "sec_intent_extra_read": "Чтение Intent extras в коде приложения (справочно).",
    "sec_intent_injection_in_exported": "Экспортируемый компонент читает Intent extras без валидации — риск инъекции Intent (CWE-927).",
    "sec_webview_js_enabled": "Включено выполнение JavaScript в WebView (справочный индикатор).",
    "sec_webview_file_xss": "WebView с включённым JS загружает содержимое из внешнего хранилища — риск XSS/инъекции (CWE-79).",
    "sec_implicit_broadcast_send": "Неявный broadcast без ограничения получателей — любое приложение может перехватить (CWE-927).",
    "sec_cleartext_http_protocol": "HTTP-протокол без шифрования для API-взаимодействия — риск MITM (CWE-319).",
    "sec_deprecated_http_client": "Устаревший HTTP-клиент Apache без гарантий TLS.",
    "sec_hardcoded_crypto_key": "Жёстко заданный криптографический ключ в исходном коде (CWE-321).",
    "sec_static_iv": "Статический или нулевой вектор инициализации ослабляет шифрование (CWE-329).",
    "vul_task_hijacking": "Экспортируемая singleTask-активность без taskAffinity допускает перехват task.",
    "supplychain_signature_invalid": "Проверка подписи завершилась ошибкой.",
    "supplychain_signature_scheme_v1_only": "Только схема подписи V1 слабее на новых версиях Android.",
    "supplychain_debug_certificate": "Отладочные сертификаты не должны использоваться в производственных сборках.",
    "supplychain_cert_expired": "Просроченные сертификаты указывают на проблемы с подписью.",
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

ENDPOINT_EXAMPLE_LIMIT = 3

SIGNING_CATEGORIES = {"supplychain_*"}
SECRET_CATEGORIES = {"secret_*"}
VULNERABILITY_CATEGORIES = {"vul_*", "sec_*"}
NDV_CATEGORIES = {"ndv_*"}
PERSISTENCE_CATEGORIES = {"persist_*"}
ANOMALY_CATEGORIES = {"anomaly_*"}
DYNAMIC_LOAD_CATEGORIES = {
    "ndv_dynamic_code_loading_dex",
    "ndv_remote_command_shell",
    "ndv_native_code_loader_suspicious",
    "ndv_reflection_heavy",
    "ndv_download_execute",
    "ndv_payload_decode_load",
}
SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}


def _category_matches(category: str, patterns: set[str]) -> bool:
    for pattern in patterns:
        if pattern.endswith("*"):
            if category.startswith(pattern[:-1]):
                return True
            continue
        if category == pattern:
            return True
    return False


def _max_severity(values: list[str]) -> str:
    if not values:
        return "info"
    return max(values, key=lambda value: SEVERITY_RANK.get(value, 0))


def _hash_id(prefix: str, *parts: str) -> str:
    payload = "|".join(part for part in parts if part)
    digest = hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()
    return f"{prefix}:{digest[:16]}"


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError:
        return None


def _duration_sec(started_at: str | None, finished_at: str | None) -> float | None:
    start_dt = _parse_dt(started_at)
    finish_dt = _parse_dt(finished_at)
    if not start_dt or not finish_dt:
        return None
    return round(max(0.0, (finish_dt - start_dt).total_seconds()), 3)


def _duration_ms(started_at: str | None, finished_at: str | None) -> int | None:
    duration = _duration_sec(started_at, finished_at)
    if duration is None:
        return None
    return int(duration * 1000)


def _map_run_status(status: str | None) -> ReportStatusV2:
    if status == "Done":
        return "ok"
    if status == "Error":
        return "fail"
    if status == "not_implemented":
        return "not_implemented"
    return "partial"


def _severity_hint(value: str | None) -> SeverityHintV2:
    if value in ("high", "medium", "low", "info"):
        return value
    return "info"


def _tool_status_from_result(status: str | None, return_code: int | None) -> ToolStatusV2:
    if status == "success":
        return "ok"
    if status == "partial":
        return "partial"
    if status == "fail":
        return "fail"
    if return_code is None:
        return "skipped"
    return "ok" if return_code == 0 else "fail"


def _source_tool(value: str | None, default_tool: str = "unknown") -> str:
    if not value:
        return default_tool
    if ":" not in value:
        return value
    return value.split(":", 1)[0]


def _source_ref(stage: str, source: str | None, default_ref: str | None = None) -> SourceRefV2:
    return SourceRefV2(stage=stage, tool=_source_tool(source), ref=default_ref, rule=source)


def _recommendation_for_category(category: str) -> str:
    if _category_matches(category, SECRET_CATEGORIES):
        return "Удалите жёстко заданные секреты и выполните ротацию затронутых учётных данных."
    if _category_matches(category, SIGNING_CATEGORIES):
        return "Исправьте конвейер подписи и проверьте корректность сертификатов и схем релизной подписи."
    if category.startswith("vul_"):
        return "Устраните небезопасную конфигурацию и добавьте регрессионные проверки."
    if category.startswith("sec_"):
        return "Примените безопасные настройки по умолчанию и перепроверьте прикладные и транспортные механизмы защиты."
    if _category_matches(category, NDV_CATEGORIES) or _category_matches(category, PERSISTENCE_CATEGORIES):
        return "Подтвердите поведение в динамическом анализе и оставьте только обоснованные возможности."
    if _category_matches(category, ANOMALY_CATEGORIES):
        return "Задокументируйте антианалитическое поведение и подтвердите его легитимность."
    return "Проверьте находку, подтвердите влияние и устраните корневую причину."


def _title_for_category(category: str) -> str:
    return translate_category(category)


def _description_for_category(category: str) -> str:
    label = translate_category(category)
    if _category_matches(category, SECRET_CATEGORIES):
        return f"Выявлен индикатор категории «{label}», связанный с встраиванием секретных данных или учётных материалов."
    if _category_matches(category, SIGNING_CATEGORIES):
        return f"Выявлена проблема категории «{label}», связанная с целостностью и корректностью подписи APK."
    if _category_matches(category, NDV_CATEGORIES) or _category_matches(category, PERSISTENCE_CATEGORIES):
        return f"Статический анализ обнаружил недекларированную возможность категории «{label}»."
    if _category_matches(category, ANOMALY_CATEGORIES):
        return f"Обнаружен аномальный или антианалитический признак категории «{label}»."
    if category.startswith("vul_") or category.startswith("sec_"):
        return f"Статический анализ выявил индикатор безопасности категории «{label}»."
    return f"Статический анализ выявил находку категории «{label}»."


def _relpath(run_dir: Path, path: Path | str) -> str:
    path_obj = Path(path)
    if not path_obj.is_absolute():
        path_obj = run_dir / path_obj
    try:
        return str(path_obj.resolve().relative_to(run_dir.resolve()))
    except (OSError, ValueError):
        return str(path)


def _safe_json(path: Path) -> dict:
    if not path.exists() or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _safe_json_any(path: Path):
    if not path.exists() or not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, ValueError):
        return None


def _line_count(path: Path) -> int:
    if not path.exists() or not path.is_file():
        return 0
    try:
        return sum(1 for _ in path.open("r", encoding="utf-8", errors="replace"))
    except OSError:
        return 0


def _extract_version(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in lines[:5]:
        text = line.strip()
        if not text:
            continue
        if re.search(r"\d+\.\d+", text):
            return text[:200]
    return None


def _endpoint_kind(finding: Finding) -> str | None:
    sources = finding.sources or []
    if any(source.startswith("rg:endpoint_url") for source in sources):
        return "url"
    if any(source.startswith("rg:endpoint_ipv4") for source in sources):
        return "ip"
    # Native strings findings: strings tool produces source "strings:secret_endpoints_*"
    if any(source.startswith("strings:secret_endpoints_hardcoded") for source in sources):
        return "url"
    if any(source.startswith("strings:secret_endpoints_ipv4") for source in sources):
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


def _collect_endpoints(findings: list[Finding]) -> tuple[dict[str, dict], dict[str, dict]]:
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
        if example and example not in entry["examples"] and len(entry["examples"]) < ENDPOINT_EXAMPLE_LIMIT:
            entry["examples"].append(example)
    return url_map, ip_map


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
        return self._write_report_files(report, run_dir, STAGE_STATIC)

    def generate_stage3(
        self,
        run: Run,
        run_dir: Path,
        mobsf_report,
        quark_report=None,
    ) -> tuple[Path, Path]:
        project = self.storage.load_project(run.project_id)
        report = self._build_stage3_report(project, run, run_dir, mobsf_report, quark_report)
        return self._write_report_files(report, run_dir, STAGE_CROSS_TOOL)

    def generate_stage2(self, run: Run, run_dir: Path, stage2_data: dict) -> tuple[Path, Path]:
        project = self.storage.load_project(run.project_id)
        report = self._build_stage2_report(project, run, run_dir, stage2_data)
        return self._write_report_files(report, run_dir, STAGE_DYNAMIC)

    def generate_stage2_stub(self, run: Run, run_dir: Path) -> tuple[Path, Path]:
        report = self._build_stub_report(run, run_dir, STAGE_DYNAMIC, "Динамический анализ")
        return self._write_report_files(report, run_dir, STAGE_DYNAMIC)

    def generate_stage3_stub(self, run: Run, run_dir: Path) -> tuple[Path, Path]:
        report = self._build_stub_report(run, run_dir, STAGE_CROSS_TOOL, "Кросс-инструментальный анализ")
        return self._write_report_files(report, run_dir, STAGE_CROSS_TOOL)

    def generate_overall_stub(self, run: Run, run_dir: Path) -> tuple[Path, Path]:
        report = self._build_stub_report(run, run_dir, STAGE_OVERALL, "Сводный отчёт")
        return self._write_report_files(report, run_dir, STAGE_OVERALL)

    def regenerate_stage1_from_json(self, run_dir: Path) -> Path | None:
        json_path, html_path = self.report_paths(run_dir, STAGE_STATIC)
        if not json_path.exists():
            return None
        payload = _safe_json(json_path)
        if payload.get("schema") != "tapka.report.v2":
            return None
        report = ReportV2.model_validate(payload)
        report.artifacts = self._collect_artifacts(run_dir, report.stage)
        html_path.write_text(render_report_html(report), encoding="utf-8")
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

    def _write_report_files(self, report: ReportV2, run_dir: Path, stage: str) -> tuple[Path, Path]:
        json_path, html_path = self.report_paths(run_dir, stage)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(report.model_dump_json(indent=2, by_alias=True), encoding="utf-8")
        html_path.write_text(render_report_html(report), encoding="utf-8")
        return json_path, html_path

    def _build_stub_report(self, run: Run, run_dir: Path, stage: str, label: str) -> ReportV2:
        project = self.storage.load_project(run.project_id)
        project_ref = self._project_ref(project, stage, run_dir)
        run_ref = self._run_ref(
            run,
            run_dir,
            status="not_implemented",
            stage_override=stage,
        )
        notes = ["Пока не реализовано.", f"Раздел «{label}» будет расширен в следующих обновлениях."]
        return ReportV2(
            report_type="stage",
            stage=stage,
            generated_at=now_utc_iso(),
            project=project_ref,
            run=run_ref,
            tools=[],
            artifacts=[],  # Stub has no artifacts belonging to this stage
            indicators=[],
            findings=[],
            sections=[
                SectionV2(
                    id="not_implemented",
                    title=label,
                    kind="text",
                    summary="Пока не реализовано.",
                    data={"status": "not_implemented"},
                )
            ],
            status="not_implemented",
            notes=notes,
        )

    def _build_stage2_report(
        self,
        project: Project,
        run: Run,
        run_dir: Path,
        stage2_data: dict,
    ) -> ReportV2:
        from analysis.stages import STAGE_DYNAMIC  # noqa: PLC0415 (avoid circular at module level)

        status = _map_run_status(run.status)
        tools = self._collect_stage2_tools(run_dir, stage2_data)

        attribution = stage2_data.get("attribution") or {}
        pkg_info = {
            "package_name": attribution.get("package_name"),
            "version_name": attribution.get("version_name"),
            "version_code": attribution.get("version_code"),
        }
        findings = self._extract_stage2_findings(stage2_data)
        return ReportV2(
            report_type="stage",
            stage=STAGE_DYNAMIC,
            generated_at=now_utc_iso(),
            project=self._project_ref(project, STAGE_DYNAMIC, run_dir, package_info=pkg_info),
            run=self._run_ref(run, run_dir, status=status),
            tools=tools,
            artifacts=self._collect_artifacts(run_dir, STAGE_DYNAMIC),
            indicators=[],
            findings=findings,
            sections=[],
            status=status,
            notes=list(run.errors) if run.errors else [],
            stage2_data=stage2_data,
        )

    def _collect_stage2_tools(self, run_dir: Path, stage2_data: dict) -> list[ToolRunV2]:
        """Build ToolRunV2 list from Stage2 tool bundles stored in run.json."""
        run_payload = _safe_json(run_dir / "run.json")
        tool_entries = run_payload.get("tools") if isinstance(run_payload.get("tools"), list) else []
        env = stage2_data.get("environment") or {}
        tool_runs: list[ToolRunV2] = []

        for i, entry in enumerate(tool_entries):
            tool_name = str(entry.get("tool") or "unknown")
            result_rel = entry.get("tool_result")
            result_path = (
                run_dir / result_rel if result_rel
                else run_dir / "tools" / tool_name / "tool_result.json"
            )
            result_data = _safe_json(result_path)

            stdout_rel = result_data.get("stdout_path")
            stderr_rel = result_data.get("stderr_path")
            if stdout_rel is None:
                cand = run_dir / "tools" / tool_name / "stdout.txt"
                if cand.exists():
                    stdout_rel = str(cand.relative_to(run_dir))
            if stderr_rel is None:
                cand = run_dir / "tools" / tool_name / "stderr.txt"
                if cand.exists():
                    stderr_rel = str(cand.relative_to(run_dir))

            ok_value = result_data.get("ok")
            exit_code = result_data.get("exit_code")
            if ok_value is True:
                t_status: ToolStatusV2 = "ok"
            elif ok_value is False:
                t_status = "fail"
            elif isinstance(exit_code, int):
                t_status = "ok" if exit_code == 0 else "fail"
            else:
                t_status = "skipped"

            metrics: dict[str, int | float | str | bool] = {}
            if isinstance(exit_code, int):
                metrics["exit_code"] = exit_code
            # Attach env metrics to first tool entry
            if i == 0 and env:
                for key in ("avd_name", "api_level", "adb_version", "boot_time_sec"):
                    val = env.get(key)
                    if isinstance(val, (bool, int, float, str)):
                        metrics[key] = val

            cmd_value = result_data.get("cmd")
            cmd = None
            if isinstance(cmd_value, list):
                cmd = " ".join(str(p) for p in cmd_value)
            elif isinstance(cmd_value, str):
                cmd = cmd_value

            outputs: dict[str, str] = {
                **({"stdout": stdout_rel} if isinstance(stdout_rel, str) else {}),
                **({"stderr": stderr_rel} if isinstance(stderr_rel, str) else {}),
                **({"result_json": _relpath(run_dir, result_path)} if result_path.exists() else {}),
            }
            artifacts_payload = result_data.get("artifacts")
            if isinstance(artifacts_payload, dict):
                for key, value in artifacts_payload.items():
                    if isinstance(key, str) and isinstance(value, str) and key not in outputs:
                        outputs[key] = value

            tool_runs.append(
                ToolRunV2(
                    tool=tool_name,
                    status=t_status,
                    version=env.get("adb_version") or None if tool_name.startswith("adb") else None,
                    cmd=cmd,
                    started_at=result_data.get("started_at"),
                    finished_at=result_data.get("finished_at"),
                    duration_ms=_duration_ms(result_data.get("started_at"), result_data.get("finished_at")),
                    outputs=outputs,
                    metrics=metrics,
                    details=None,
                )
            )

        # Fall back to single env-based entry when no tool bundles recorded
        if not tool_runs and env:
            tool_runs.append(
                ToolRunV2(
                    tool="adb",
                    status="ok",
                    version=env.get("adb_version") or "",
                    cmd="adb",
                    started_at=None,
                    finished_at=None,
                    duration_ms=None,
                    outputs={},
                    metrics={
                        "boot_time_sec": env.get("boot_time_sec", 0),
                        "avd_name": env.get("avd_name", ""),
                        "api_level": env.get("api_level", 0),
                    },
                    details=None,
                )
            )
        return tool_runs

    def _extract_stage2_findings(self, stage2_data: dict) -> list[FindingV2]:
        """Lift stage2_data.findings into top-level FindingV2 list."""
        raw = stage2_data.get("findings") or []
        result: list[FindingV2] = []
        for f in raw:
            if not isinstance(f, dict):
                continue
            finding_id = f.get("finding_id", "")
            confidence = f.get("confidence", "C1")
            if confidence not in ("C1", "C2", "C3"):
                confidence = "C1"
            # Map confidence to severity hint
            sev: SeverityHintV2 = "info"
            if confidence == "C3":
                sev = "high"
            elif confidence == "C2":
                sev = "medium"
            title = f.get("title", "")
            if not title:
                continue
            detail = f.get("detail", "")
            evidence_val = f.get("evidence", "")
            evidence_items: list[EvidenceItemV2] = []
            if evidence_val:
                evidence_items.append(
                    EvidenceItemV2(
                        kind="file",
                        file=str(evidence_val),
                        line=None,
                        snippet=detail[:300] if detail else None,
                        ref=str(evidence_val),
                    )
                )
            result.append(
                FindingV2(
                    id=_hash_id("fnd", "stage2", finding_id),
                    category=finding_id or "stage2_finding",
                    title=title,
                    severity=sev,
                    confidence=confidence,  # type: ignore[arg-type]
                    tags=["stage2", "dynamic"],
                    description=detail,
                    recommendation="",
                    evidence=evidence_items,
                    sources=[
                        SourceRefV2(
                            stage=STAGE_DYNAMIC,
                            tool="stage2",
                            ref="artifacts/stage2_findings.json",
                            rule=finding_id or None,
                        )
                    ],
                    related_indicators=[],
                )
            )
        return result

    def _build_stage1_report(
        self,
        project: Project,
        run: Run,
        run_dir: Path,
        findings: list[Finding],
    ) -> ReportV2:
        package_info = self._parse_package_info(run_dir)
        tools = self._build_stage1_tools(run, run_dir)
        indicators = self._build_stage1_indicators(run_dir, findings)
        indicator_index = self._indicator_index(indicators)
        findings_v2 = self._build_stage1_findings(findings, indicator_index)
        sections = self._build_stage1_sections(run_dir, findings)
        status = self._derive_report_status(_map_run_status(run.status), tools)

        return ReportV2(
            report_type="stage",
            stage=STAGE_STATIC,
            generated_at=now_utc_iso(),
            project=self._project_ref(project, STAGE_STATIC, run_dir, package_info=package_info),
            run=self._run_ref(run, run_dir, status=status),
            tools=tools,
            artifacts=self._collect_artifacts(run_dir, STAGE_STATIC),
            indicators=indicators,
            findings=findings_v2,
            sections=sections,
            status=status,
            notes=list(run.errors),
        )

    def _build_stage3_report(
        self,
        project: Project,
        run: Run,
        run_dir: Path,
        mobsf_report,
        quark_report,
    ) -> ReportV2:
        stage3_data = self._collect_stage3_data(run_dir, mobsf_report, quark_report)
        tools = self._build_stage3_tools(run_dir, stage3_data)
        indicators = self._build_stage3_indicators(run_dir, stage3_data)
        indicator_index = self._indicator_index(indicators)
        findings = self._build_stage3_findings(stage3_data, indicator_index)
        sections = self._build_stage3_sections(run_dir, stage3_data, tools)
        status = self._derive_report_status(_map_run_status(run.status), tools)

        package_info = {}
        mobsf_data = stage3_data.get("mobsf") if isinstance(stage3_data, dict) else None
        if isinstance(mobsf_data, dict):
            package_info = {
                "package_name": mobsf_data.get("package_name"),
                "version_name": mobsf_data.get("version_name"),
                "version_code": mobsf_data.get("version_code"),
            }

        return ReportV2(
            report_type="stage",
            stage=STAGE_CROSS_TOOL,
            generated_at=now_utc_iso(),
            project=self._project_ref(project, STAGE_CROSS_TOOL, run_dir, package_info=package_info),
            run=self._run_ref(run, run_dir, status=status),
            tools=tools,
            artifacts=self._collect_artifacts(run_dir, STAGE_CROSS_TOOL),
            indicators=indicators,
            findings=findings,
            sections=sections,
            status=status,
            notes=list(run.errors),
        )

    def _project_ref(
        self,
        project: Project,
        stage: str,
        run_dir: Path,
        package_info: dict | None = None,
    ) -> ProjectInfoV2:
        _ = stage
        apk_path = self.storage.get_apk_path(project.project_id)
        apk_meta = project.apk_meta
        package_info = package_info or {}
        return ProjectInfoV2(
            project_id=project.project_id,
            apk_name=apk_meta.name if apk_meta else None,
            apk_path=str(apk_path) if apk_path else None,
            apk_sha256=apk_meta.sha256 if apk_meta else None,
            apk_size=apk_meta.size if apk_meta else None,
            package_name=package_info.get("package_name"),
            version_name=package_info.get("version_name"),
            version_code=(
                str(package_info.get("version_code")) if package_info.get("version_code") is not None else None
            ),
        )

    def _run_ref(
        self,
        run: Run,
        run_dir: Path,
        status: ReportStatusV2 | None = None,
        stage_override: str | None = None,
    ) -> RunInfoV2:
        final_status = status or _map_run_status(run.status)
        duration = _duration_sec(run.started_at, run.finished_at)
        return RunInfoV2(
            run_id=run.run_id,
            stage=stage_override or run.stage,
            status=final_status,
            started_at=run.started_at,
            finished_at=run.finished_at,
            duration_sec=duration,
            run_dir=str(run_dir),
        )

    def _build_stage1_tools(self, run: Run, run_dir: Path) -> list[ToolRunV2]:
        tools: list[ToolRunV2] = []
        for result in run.command_results:
            stdout_rel = _relpath(run_dir, result.stdout_path)
            stderr_rel = _relpath(run_dir, result.stderr_path)
            stdout_path = run_dir / stdout_rel
            metrics: dict[str, int | float | str | bool] = {}
            if result.return_code is not None:
                metrics["return_code"] = result.return_code
            if result.timed_out:
                metrics["timed_out"] = True

            if result.tool == "rg":
                metrics["matches"] = _line_count(stdout_path)
            elif result.tool == "jadx":
                metrics["errors"] = self._parse_jadx_errors_for_output(stdout_path, run_dir / stderr_rel)
            elif result.tool == "yara":
                matches, rules = self._parse_yara_matches_for_output(stdout_path)
                metrics["matches"] = matches
                metrics["rules"] = rules

            details = result.error
            if not details and result.timed_out:
                details = "Command timed out"

            tools.append(
                ToolRunV2(
                    tool=result.tool,
                    status=_tool_status_from_result(result.status, result.return_code),
                    version=_extract_version(stdout_path),
                    cmd=" ".join(result.argv),
                    started_at=None,
                    finished_at=None,
                    duration_ms=int(result.duration_sec * 1000),
                    outputs={
                        "stdout": stdout_rel,
                        "stderr": stderr_rel,
                    },
                    metrics=metrics,
                    details=details,
                )
            )

        for tool in run.tools_missing:
            tools.append(
                ToolRunV2(
                    tool=tool,
                    status="fail",
                    details="Tool is missing in PATH",
                )
            )

        return tools

    def _build_stage3_tools(self, run_dir: Path, stage3_data: dict[str, dict]) -> list[ToolRunV2]:
        run_payload = _safe_json(run_dir / "run.json")
        tool_entries = run_payload.get("tools") if isinstance(run_payload.get("tools"), list) else []
        tool_runs: list[ToolRunV2] = []

        if not tool_entries:
            tools_dir = run_dir / "tools"
            if tools_dir.exists():
                for tool_dir in sorted(path for path in tools_dir.iterdir() if path.is_dir()):
                    tool_entries.append(
                        {
                            "tool": tool_dir.name,
                            "tool_result": str((tool_dir / "tool_result.json").relative_to(run_dir)),
                        }
                    )

        known_tools = ("mobsf", "quark", "apkid", "apkleaks")
        existing_names = {str(entry.get("tool") or "unknown") for entry in tool_entries if isinstance(entry, dict)}
        for tool_name in known_tools:
            tool_root = run_dir / "tools" / tool_name
            tool_data = stage3_data.get(tool_name, {})
            has_payload = bool(tool_data.get("present"))
            if tool_name in existing_names:
                continue
            if tool_root.exists() or has_payload:
                tool_entries.append(
                    {
                        "tool": tool_name,
                        "tool_result": str((tool_root / "tool_result.json").relative_to(run_dir)),
                    }
                )

        for entry in tool_entries:
            tool_name = str(entry.get("tool") or "unknown")
            result_rel = entry.get("tool_result")
            result_path = run_dir / result_rel if result_rel else run_dir / "tools" / tool_name / "tool_result.json"
            result_data = _safe_json(result_path)

            stdout_rel = result_data.get("stdout_path")
            stderr_rel = result_data.get("stderr_path")
            if stdout_rel is None:
                stdout_candidate = run_dir / "tools" / tool_name / "stdout.txt"
                if stdout_candidate.exists():
                    stdout_rel = str(stdout_candidate.relative_to(run_dir))
            if stderr_rel is None:
                stderr_candidate = run_dir / "tools" / tool_name / "stderr.txt"
                if stderr_candidate.exists():
                    stderr_rel = str(stderr_candidate.relative_to(run_dir))

            ok_value = result_data.get("ok")
            exit_code = result_data.get("exit_code")
            reported_status = str(result_data.get("status") or "").strip().lower()
            if reported_status in ("ok", "success"):
                status: ToolStatusV2 = "ok"
            elif reported_status in ("partial",):
                status = "partial"
            elif reported_status in ("fail", "failed", "error"):
                status = "fail"
            elif ok_value is True:
                status = "ok"
            elif ok_value is False:
                status = "fail"
            elif isinstance(exit_code, int):
                status = "ok" if exit_code == 0 else "fail"
            else:
                status = "skipped"

            stderr_path = run_dir / stderr_rel if isinstance(stderr_rel, str) else None
            details = None
            if status == "fail" and stderr_path and stderr_path.exists():
                try:
                    first_line = stderr_path.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    first_line = []
                if first_line:
                    details = first_line[0][:300]

            metrics: dict[str, int | float | str | bool] = {}
            if isinstance(exit_code, int):
                metrics["exit_code"] = exit_code

            data_payload = result_data.get("data")
            if isinstance(data_payload, dict):
                for key, value in data_payload.items():
                    if isinstance(value, (bool, int, float, str)):
                        metrics[key] = value

            tool_data = stage3_data.get(tool_name, {})
            if tool_name == "mobsf":
                for key in (
                    "security_score",
                    "urls_total",
                    "permissions_total",
                    "exported_total",
                    "findings_high",
                    "findings_warning",
                ):
                    value = tool_data.get(key)
                    if isinstance(value, (int, float)):
                        metrics[key] = value
                version = tool_data.get("version")
                if isinstance(version, str) and version and "version" not in metrics:
                    metrics["version"] = version
            if tool_name == "quark":
                for key in ("rules_total", "rules_matched", "total_score"):
                    value = tool_data.get(key)
                    if isinstance(value, (int, float)):
                        metrics[key] = value
                threat_level = tool_data.get("threat_level")
                if isinstance(threat_level, str) and threat_level:
                    metrics["threat_level"] = threat_level
            if tool_name == "apkid":
                for key in ("files_total", "matches_total"):
                    value = tool_data.get(key)
                    if isinstance(value, int):
                        metrics[key] = value
                apkid_version = tool_data.get("apkid_version")
                if isinstance(apkid_version, str) and apkid_version:
                    metrics["apkid_version"] = apkid_version
            if tool_name == "apkleaks":
                for key in ("groups_total", "leaks_total"):
                    value = tool_data.get(key)
                    if isinstance(value, int):
                        metrics[key] = value

            cmd_value = result_data.get("cmd")
            cmd = None
            if isinstance(cmd_value, list):
                cmd = " ".join(str(part) for part in cmd_value)
            elif isinstance(cmd_value, str):
                cmd = cmd_value

            outputs: dict[str, str] = {
                **({"stdout": stdout_rel} if isinstance(stdout_rel, str) else {}),
                **({"stderr": stderr_rel} if isinstance(stderr_rel, str) else {}),
                **({"result_json": _relpath(run_dir, result_path)} if result_path.exists() else {}),
            }
            artifacts_payload = result_data.get("artifacts")
            if isinstance(artifacts_payload, dict):
                for key, value in artifacts_payload.items():
                    if not isinstance(key, str) or not isinstance(value, str):
                        continue
                    if key in outputs:
                        outputs[f"artifact_{key}"] = value
                    else:
                        outputs[key] = value

            # For APKiD: stdout is JSON, so _extract_version would return JSON text.
            # Use apkid_version from metrics when available.
            if tool_name == "apkid" and "apkid_version" in metrics:
                version: str | None = str(metrics["apkid_version"])
            else:
                version = _extract_version(run_dir / stdout_rel) if isinstance(stdout_rel, str) else None

            tool_runs.append(
                ToolRunV2(
                    tool=tool_name,
                    status=status,
                    version=version,
                    cmd=cmd,
                    started_at=result_data.get("started_at"),
                    finished_at=result_data.get("finished_at"),
                    duration_ms=_duration_ms(result_data.get("started_at"), result_data.get("finished_at")),
                    outputs=outputs,
                    metrics=metrics,
                    details=details,
                )
            )

        return tool_runs

    def _build_stage1_indicators(self, run_dir: Path, findings: list[Finding]) -> list[IndicatorV2]:
        indicators: list[IndicatorV2] = []
        url_map, ip_map = _collect_endpoints(findings)

        for value, entry in sorted(url_map.items()):
            examples = [
                IndicatorExampleV2(file=example.get("path"), line=example.get("line"), snippet=None)
                for example in entry.get("examples", [])
            ]
            indicators.append(
                IndicatorV2(
                    id=_hash_id("ind", "url", value),
                    type="url",
                    value=value,
                    severity_hint="low",
                    noise=bool(entry.get("noise")),
                    tags=["network"],
                    sources=[
                        SourceRefV2(
                            stage=STAGE_STATIC,
                            tool="rg",
                            ref="artifacts/endpoints.urls.json",
                            rule="rg:endpoint_url",
                        )
                    ],
                    examples=examples,
                )
            )

        for value, entry in sorted(ip_map.items()):
            examples = [
                IndicatorExampleV2(file=example.get("path"), line=example.get("line"), snippet=None)
                for example in entry.get("examples", [])
            ]
            indicators.append(
                IndicatorV2(
                    id=_hash_id("ind", "ip", value),
                    type="ip",
                    value=value,
                    severity_hint="low",
                    noise=False,
                    tags=["network"],
                    sources=[
                        SourceRefV2(
                            stage=STAGE_STATIC,
                            tool="rg",
                            ref="artifacts/endpoints.ips.json",
                            rule="rg:endpoint_ipv4",
                        )
                    ],
                    examples=examples,
                )
            )

        manifest = self._manifest_summary(run_dir)
        for permission in manifest["permissions"]:
            indicators.append(
                IndicatorV2(
                    id=_hash_id("ind", "permission", permission),
                    type="permission",
                    value=permission,
                    severity_hint="info",
                    tags=["manifest"],
                    sources=[
                        SourceRefV2(
                            stage=STAGE_STATIC,
                            tool="manifest",
                            ref="artifacts/out_apktool/AndroidManifest.xml",
                        )
                    ],
                )
            )

        for exported in manifest["exported"]:
            indicators.append(
                IndicatorV2(
                    id=_hash_id("ind", "exported_component", exported),
                    type="exported_component",
                    value=exported,
                    severity_hint="medium",
                    tags=["manifest", "exported"],
                    sources=[
                        SourceRefV2(
                            stage=STAGE_STATIC,
                            tool="manifest",
                            ref="artifacts/out_apktool/AndroidManifest.xml",
                        )
                    ],
                )
            )

        signing_summary = self._signing_summary(findings)
        for category, count in sorted(signing_summary.items()):
            indicators.append(
                IndicatorV2(
                    id=_hash_id("ind", "signing", category),
                    type="signing_issue",
                    value=category,
                    severity_hint="high" if category == "supplychain_signature_invalid" else "medium",
                    tags=["signing"],
                    sources=[
                        SourceRefV2(
                            stage=STAGE_STATIC,
                            tool="apksigner",
                            ref="logs/apksigner.stdout.txt",
                            rule=category,
                        )
                    ],
                    examples=[IndicatorExampleV2(file="logs/apksigner.stdout.txt", line=None, snippet=f"count={count}")],
                )
            )

        return indicators

    def _build_stage3_indicators(self, run_dir: Path, stage3_data: dict[str, dict]) -> list[IndicatorV2]:
        normalized_path = run_dir / "normalized" / "indicators.json"
        payload = _safe_json_any(normalized_path)
        indicators: list[IndicatorV2] = []

        items = None
        if isinstance(payload, dict):
            raw_items = payload.get("items")
            if isinstance(raw_items, list):
                items = raw_items
        elif isinstance(payload, list):
            items = payload

        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict):
                    continue
                value = str(item.get("value") or "").strip()
                indicator_type = str(item.get("kind") or item.get("type") or "indicator").strip()
                if not value or not indicator_type:
                    continue
                sources: list[SourceRefV2] = []
                examples: list[IndicatorExampleV2] = []
                evidence = item.get("evidence")
                if isinstance(evidence, list):
                    for evidence_item in evidence:
                        if not isinstance(evidence_item, dict):
                            continue
                        tool = str(evidence_item.get("tool") or "stage3")
                        ref = evidence_item.get("path")
                        locator = evidence_item.get("locator")
                        sources.append(
                            SourceRefV2(
                                stage=STAGE_CROSS_TOOL,
                                tool=tool,
                                ref=ref if isinstance(ref, str) else None,
                                rule=None,
                            )
                        )
                        examples.append(
                            IndicatorExampleV2(
                                file=ref if isinstance(ref, str) else None,
                                line=None,
                                snippet=str(locator) if locator is not None else None,
                            )
                        )
                indicator_id = item.get("id")
                if not isinstance(indicator_id, str) or not indicator_id:
                    indicator_id = _hash_id("ind", indicator_type, value)
                tags = item.get("tags") if isinstance(item.get("tags"), list) else []
                indicators.append(
                    IndicatorV2(
                        id=indicator_id,
                        type=indicator_type,
                        value=value,
                        severity_hint=_severity_hint(item.get("severity") or item.get("priority")),
                        noise=False,
                        tags=[str(tag) for tag in tags],
                        sources=sources,
                        examples=examples,
                    )
                )

        seen_keys = {(item.type, item.value) for item in indicators}

        def append_unique(indicator: IndicatorV2) -> None:
            key = (indicator.type, indicator.value)
            if key in seen_keys:
                return
            seen_keys.add(key)
            indicators.append(indicator)

        mobsf_data = stage3_data.get("mobsf", {})
        mobsf_ref = mobsf_data.get("ref") if isinstance(mobsf_data.get("ref"), str) else "artifacts/mobsf/static/report.json"
        for value in mobsf_data.get("urls_top", []) or []:
            append_unique(
                IndicatorV2(
                    id=_hash_id("ind", "url", str(value)),
                    type="url",
                    value=str(value),
                    severity_hint="low",
                    tags=["network"],
                    sources=[SourceRefV2(stage=STAGE_CROSS_TOOL, tool="mobsf", ref=mobsf_ref)],
                )
            )
        for value in mobsf_data.get("domains_top", []) or []:
            append_unique(
                IndicatorV2(
                    id=_hash_id("ind", "domain", str(value)),
                    type="domain",
                    value=str(value),
                    severity_hint="low",
                    tags=["network"],
                    sources=[SourceRefV2(stage=STAGE_CROSS_TOOL, tool="mobsf", ref=mobsf_ref)],
                )
            )
        for value in mobsf_data.get("permissions_top", []) or []:
            append_unique(
                IndicatorV2(
                    id=_hash_id("ind", "permission", str(value)),
                    type="permission",
                    value=str(value),
                    severity_hint="info",
                    tags=["manifest"],
                    sources=[SourceRefV2(stage=STAGE_CROSS_TOOL, tool="mobsf", ref=mobsf_ref)],
                )
            )

        quark_data = stage3_data.get("quark", {})
        quark_ref = quark_data.get("ref") if isinstance(quark_data.get("ref"), str) else "tools/quark/quark_output.json"
        for item in quark_data.get("crimes", []) or []:
            if not isinstance(item, dict):
                continue
            rule_name = str(item.get("rule") or item.get("rule_name") or "").strip()
            crime = str(item.get("crime") or "").strip()
            value = crime or rule_name
            if not value:
                continue
            tags = item.get("label")
            tags = [str(tag) for tag in tags] if isinstance(tags, list) else []
            score = item.get("score")
            severity_hint: SeverityHintV2 = "low"
            if isinstance(score, (int, float)) and score >= 1:
                severity_hint = "medium"
            append_unique(
                IndicatorV2(
                    id=_hash_id("ind", "quark_finding", value, rule_name),
                    type="quark_finding",
                    value=value,
                    severity_hint=severity_hint,
                    tags=tags or ["rule_match"],
                    sources=[
                        SourceRefV2(
                            stage=STAGE_CROSS_TOOL,
                            tool="quark",
                            ref=quark_ref,
                            rule=rule_name or None,
                        )
                    ],
                )
            )

        apkid_data = stage3_data.get("apkid", {})
        apkid_ref = apkid_data.get("ref") if isinstance(apkid_data.get("ref"), str) else "tools/apkid/raw/apkid.json"
        for item in apkid_data.get("matches", []) or []:
            if not isinstance(item, dict):
                continue
            category = str(item.get("category") or "").strip()
            value = str(item.get("value") or "").strip()
            if not category or not value:
                continue
            append_unique(
                IndicatorV2(
                    id=_hash_id("ind", "apkid_match", category, value),
                    type="apkid_match",
                    value=f"{category}: {value}",
                    severity_hint="low",
                    tags=["apkid"],
                    sources=[SourceRefV2(stage=STAGE_CROSS_TOOL, tool="apkid", ref=apkid_ref, rule=category)],
                    examples=[
                        IndicatorExampleV2(
                            file=item.get("file_path") if isinstance(item.get("file_path"), str) else None,
                            line=None,
                            snippet=None,
                        )
                    ],
                )
            )

        apkleaks_data = stage3_data.get("apkleaks", {})
        apkleaks_ref = (
            apkleaks_data.get("ref") if isinstance(apkleaks_data.get("ref"), str) else "tools/apkleaks/raw/apkleaks.json"
        )
        for item in apkleaks_data.get("entries", []) or []:
            if not isinstance(item, dict):
                continue
            value = str(item.get("value") or "").strip()
            if not value:
                continue
            group_name = str(item.get("group") or "").strip() or "неизвестно"
            append_unique(
                IndicatorV2(
                    id=_hash_id("ind", "apkleaks", group_name, value),
                    type="apkleaks_leak",
                    value=value,
                    severity_hint="low",
                    tags=["apkleaks", group_name.lower()],
                    sources=[
                        SourceRefV2(
                            stage=STAGE_CROSS_TOOL,
                            tool="apkleaks",
                            ref=apkleaks_ref,
                            rule=group_name,
                        )
                    ],
                    examples=[
                        IndicatorExampleV2(
                            file=item.get("file_path") if isinstance(item.get("file_path"), str) else "-",
                            line=None,
                            snippet=group_name,
                        )
                    ],
                )
            )

        return indicators

    def _indicator_index(self, indicators: list[IndicatorV2]) -> dict[str, list[str]]:
        index: dict[str, list[str]] = {}
        for indicator in indicators:
            index.setdefault(indicator.value, []).append(indicator.id)
        return index

    def _build_stage1_findings(
        self,
        findings: list[Finding],
        indicator_index: dict[str, list[str]],
    ) -> list[FindingV2]:
        converted: list[FindingV2] = []
        for finding in findings:
            evidence_value = (finding.evidence or finding.match or "").strip()
            location = finding.location or finding.file_path or ""
            finding_id = _hash_id("fnd", finding.category, evidence_value, location)

            sources = [
                _source_ref(STAGE_STATIC, source, default_ref=None)
                for source in (finding.sources or ([finding.source] if finding.source else []))
            ]
            if not sources:
                sources = [SourceRefV2(stage=STAGE_STATIC, tool="stage1", ref=None)]

            related = list(indicator_index.get(evidence_value, []))
            related.extend(indicator_index.get(finding.category, []))
            related_indicators = sorted(set(related))

            converted.append(
                FindingV2(
                    id=finding_id,
                    category=finding.category,
                    title=_title_for_category(finding.category),
                    severity=_severity_hint(finding.severity),
                    confidence=finding.confidence if finding.confidence in ("C1", "C2", "C3") else "C1",
                    tags=sorted(set(finding.tags or set())),
                    description=_description_for_category(finding.category),
                    recommendation=_recommendation_for_category(finding.category),
                    evidence=[
                        EvidenceItemV2(
                            kind=finding.evidence_type or "string",
                            file=finding.file_path or None,
                            line=finding.line,
                            snippet=evidence_value or None,
                            ref=location or None,
                        )
                    ],
                    sources=sources,
                    related_indicators=related_indicators,
                )
            )
        return converted

    def _build_stage3_findings(
        self,
        stage3_data: dict[str, dict],
        indicator_index: dict[str, list[str]],
    ) -> list[FindingV2]:
        findings: list[FindingV2] = []

        mobsf_data = stage3_data.get("mobsf", {})
        mobsf_ref = mobsf_data.get("ref") if isinstance(mobsf_data.get("ref"), str) else "artifacts/mobsf/static/report.json"
        severity_sets = (
            ("high", mobsf_data.get("appsec_high", []) or []),
            ("medium", mobsf_data.get("appsec_warning", []) or []),
        )
        for severity, entries in severity_sets:
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                title = str(entry.get("title") or "").strip()
                if not title:
                    continue
                section = str(entry.get("section") or "").strip()
                description = str(entry.get("description") or "").strip()
                related = list(indicator_index.get(title, []))
                if section:
                    related.extend(indicator_index.get(section, []))
                findings.append(
                    FindingV2(
                        id=_hash_id("fnd", "mobsf", title, section),
                        category="mobsf_appsec",
                        title=title,
                        severity=_severity_hint(severity),
                        confidence="C2",
                        tags=["mobsf"],
                        description=description or "Замечание AppSec из отчёта MobSF.",
                        recommendation="Проверьте замечание MobSF и примените рекомендуемую меру защиты.",
                        evidence=[
                            EvidenceItemV2(
                                kind="code",
                                file=mobsf_ref,
                                line=None,
                                snippet=section or title,
                                ref=mobsf_ref,
                            )
                        ],
                        sources=[
                            SourceRefV2(
                                stage=STAGE_CROSS_TOOL,
                                tool="mobsf",
                                ref=mobsf_ref,
                                rule=section or None,
                            )
                        ],
                        related_indicators=sorted(set(related)),
                    )
                )

        quark_data = stage3_data.get("quark", {})
        quark_ref = quark_data.get("ref") if isinstance(quark_data.get("ref"), str) else "tools/quark/quark_output.json"
        from analysis.quark.runner import _quark_is_matched  # noqa: PLC0415
        for item in quark_data.get("crimes", []) or []:
            if not isinstance(item, dict):
                continue
            if not _quark_is_matched(item):
                continue
            rule_name = str(item.get("rule") or item.get("rule_name") or "").strip()
            crime = str(item.get("crime") or "").strip()
            score = item.get("score")
            finding_severity: SeverityHintV2 = "low"
            if isinstance(score, (int, float)) and score > 2.0:
                finding_severity = "high"
            elif isinstance(score, (int, float)) and score >= 1:
                finding_severity = "medium"
            title = crime or f"Сработало правило Quark: {rule_name}"
            if not title:
                continue
            related = list(indicator_index.get(title, []))
            if rule_name:
                related.extend(indicator_index.get(rule_name, []))
            tags = item.get("label")
            tags = [str(tag) for tag in tags] if isinstance(tags, list) else ["quark"]
            findings.append(
                FindingV2(
                    id=_hash_id("fnd", "quark", rule_name, title),
                    category="quark_rule_match",
                    title=title,
                    severity=finding_severity,
                    confidence="C2",
                    tags=tags,
                    description="Quark выявил подозрительный поведенческий шаблон.",
                    recommendation="Проверьте корректность срабатывания правила и исследуйте затронутый путь выполнения кода.",
                    evidence=[
                        EvidenceItemV2(
                            kind="code",
                            file=quark_ref,
                            line=None,
                            snippet=rule_name or title,
                            ref=quark_ref,
                        )
                    ],
                    sources=[
                        SourceRefV2(
                            stage=STAGE_CROSS_TOOL,
                            tool="quark",
                            ref=quark_ref,
                            rule=rule_name or None,
                        )
                    ],
                    related_indicators=sorted(set(related)),
                )
            )

        apkid_data = stage3_data.get("apkid", {})
        apkid_ref = apkid_data.get("ref") if isinstance(apkid_data.get("ref"), str) else "tools/apkid/raw/apkid.json"
        for item in apkid_data.get("matches", []) or []:
            if not isinstance(item, dict):
                continue
            category = str(item.get("category") or "").strip()
            value = str(item.get("value") or "").strip()
            file_path = str(item.get("file_path") or "-")
            if not category or not value:
                continue
            evidence_value = f"{category}: {value}"
            related = list(indicator_index.get(evidence_value, []))
            findings.append(
                FindingV2(
                    id=_hash_id("fnd", "apkid", category, value, file_path),
                    category="apkid_match",
                    title=f"Совпадение APKiD: {category}",
                    severity="low",
                    confidence="C2",
                    tags=["apkid", category],
                    description="APKiD обнаружил сигнатуру упаковщика, обфускации или механизма защиты.",
                    recommendation="Проверьте, являются ли обнаруженные упаковщики и антианалитические механизмы ожидаемыми для приложения.",
                    evidence=[
                        EvidenceItemV2(
                            kind="string",
                            file=file_path,
                            line=None,
                            snippet=value,
                            ref=apkid_ref,
                        )
                    ],
                    sources=[SourceRefV2(stage=STAGE_CROSS_TOOL, tool="apkid", ref=apkid_ref, rule=category)],
                    related_indicators=sorted(set(related)),
                )
            )

        apkleaks_data = stage3_data.get("apkleaks", {})
        apkleaks_ref = (
            apkleaks_data.get("ref") if isinstance(apkleaks_data.get("ref"), str) else "tools/apkleaks/raw/apkleaks.json"
        )
        for group in apkleaks_data.get("groups", []) or []:
            if not isinstance(group, dict):
                continue
            group_name = str(group.get("name") or "").strip()
            count = group.get("count")
            examples = group.get("examples")
            first_value = ""
            if isinstance(examples, list) and examples:
                first_value = str(examples[0])
            if not group_name:
                continue
            related = list(indicator_index.get(first_value, []))
            lowered = group_name.lower()
            finding_severity: SeverityHintV2 = "low"
            if any(token in lowered for token in ("secret", "password", "private", "token", "key")):
                finding_severity = "medium"
            category_slug = re.sub(r"[^a-z0-9]+", "_", lowered).strip("_") or "generic"
            findings.append(
                FindingV2(
                    id=_hash_id("fnd", "apkleaks", group_name, str(count)),
                    category=f"apkleaks_{category_slug}",
                    title=f"Группа APKLeaks: {group_name}",
                    severity=finding_severity,
                    confidence="C1",
                    tags=["apkleaks", group_name],
                    description=f"APKLeaks выявил {count if isinstance(count, int) else 0} совпадений в группе {group_name}.",
                    recommendation="Проверьте найденные значения и удалите из APK непубличные секреты и конфиденциальную конфигурацию.",
                    evidence=[
                        EvidenceItemV2(
                            kind="string",
                            file="-",
                            line=None,
                            snippet=first_value or f"group={group_name}",
                            ref=apkleaks_ref,
                        )
                    ],
                    sources=[SourceRefV2(stage=STAGE_CROSS_TOOL, tool="apkleaks", ref=apkleaks_ref, rule=group_name)],
                    related_indicators=sorted(set(related)),
                )
            )

        return findings

    def _build_stage1_sections(self, run_dir: Path, findings: list[Finding]) -> list[SectionV2]:
        manifest = self._manifest_summary(run_dir)
        endpoints = self._endpoint_summary(findings)
        signing = self._signing_summary(findings)
        findings_by_category = self._group_findings(findings)
        signing_details = self._signing_details(run_dir, signing)
        native_strings = self._native_strings_summary(run_dir)

        manifest_ref = "artifacts/out_apktool/AndroidManifest.xml"
        if not (run_dir / manifest_ref).exists():
            manifest_ref = None

        sections = [
            SectionV2(
                id="manifest",
                title="Манифест",
                kind="json_ref",
                summary=(
                    f"разрешений={len(manifest['permissions'])}, "
                    f"экспортируемых={len(manifest['exported'])}, "
                    f"флагов={len(manifest['flags'])}"
                ),
                ref=manifest_ref,
                data=manifest,
            ),
            SectionV2(
                id="endpoints",
                title="Конечные точки",
                kind="table",
                summary=f"URL={endpoints['urls']}, IP={endpoints['ips']}",
                ref="artifacts/endpoints.urls.json",
                data={
                    "summary": endpoints,
                    "refs": ["artifacts/endpoints.urls.json", "artifacts/endpoints.ips.json"],
                },
            ),
            SectionV2(
                id="signing",
                title="Подпись",
                kind="table",
                summary=f"замечаний={sum(signing.values())}",
                ref="logs/apksigner.stdout.txt",
                data=signing,
            ),
            SectionV2(
                id="signing_details",
                title="Сведения о подписи",
                kind="json_ref",
                summary=(
                    f"схем={len(signing_details.get('schemes', {}))}, "
                    f"замечаний={signing_details.get('issues_total', 0)}"
                ),
                ref="logs/apksigner.stdout.txt",
                data=signing_details,
            ),
            SectionV2(
                id="findings_by_category",
                title="Находки по категориям",
                kind="table",
                summary=f"категорий={len(findings_by_category)}",
                ref="findings/findings.json",
                data=findings_by_category,
            ),
            SectionV2(
                id="native_strings",
                title="Строки нативных библиотек",
                kind="json_ref",
                summary=(
                    f".so-файлов={native_strings.get('so_files', 0)}, "
                    f"совпадений={native_strings.get('hits_total', 0)}"
                ),
                ref=native_strings.get("ref"),
                data=native_strings,
            ),
        ]
        return sections

    def _build_stage3_sections(self, run_dir: Path, stage3_data: dict[str, dict], tools: list[ToolRunV2]) -> list[SectionV2]:
        sections: list[SectionV2] = []

        normalized_ref = "normalized/indicators.json"
        if (run_dir / normalized_ref).exists():
            sections.append(
                SectionV2(
                    id="normalized_indicators",
                    title="Нормализованные индикаторы",
                    kind="json_ref",
                    summary="Нормализованные индикаторы этапа 3 для ручной проверки.",
                    ref=normalized_ref,
                    data=None,
                )
            )

        mobsf_data = stage3_data.get("mobsf", {})
        mobsf_ref = mobsf_data.get("ref") if isinstance(mobsf_data.get("ref"), str) else "artifacts/mobsf/static/report.json"
        if (run_dir / mobsf_ref).exists() or mobsf_data.get("present"):
            score = mobsf_data.get("security_score")
            summary = (
                f"Оценка безопасности MobSF={score}"
                if isinstance(score, (int, float))
                else "Артефакты MobSF и извлечённая сводка."
            )
            sections.append(
                SectionV2(
                    id="mobsf",
                    title="MobSF",
                    kind="json_ref",
                    summary=summary,
                    ref=mobsf_ref if (run_dir / mobsf_ref).exists() else None,
                    data=None,
                )
            )
            sections.append(
                SectionV2(
                    id="mobsf_details",
                    title="Сведения MobSF",
                    kind="json_ref",
                    summary=(
                        f"критичных={mobsf_data.get('findings_high', 0)}, "
                        f"предупреждений={mobsf_data.get('findings_warning', 0)}"
                    ),
                    ref=mobsf_ref if (run_dir / mobsf_ref).exists() else None,
                    data={
                        "security_score": mobsf_data.get("security_score"),
                        "appsec_high": mobsf_data.get("appsec_high", []),
                        "appsec_warning": mobsf_data.get("appsec_warning", []),
                        "urls_top": mobsf_data.get("urls_top", []),
                        "domains_top": mobsf_data.get("domains_top", []),
                    },
                )
            )

        quark_data = stage3_data.get("quark", {})
        quark_ref = quark_data.get("ref") if isinstance(quark_data.get("ref"), str) else "tools/quark/quark_output.json"
        if (run_dir / quark_ref).exists() or quark_data.get("present"):
            matched = quark_data.get("rules_matched")
            total = quark_data.get("rules_total")
            summary = (
                f"Сработавших правил Quark={matched}/{total}"
                if isinstance(matched, int) and isinstance(total, int)
                else "Результаты выполнения правил Quark."
            )
            sections.append(
                SectionV2(
                    id="quark",
                    title="Quark",
                    kind="json_ref",
                    summary=summary,
                    ref=quark_ref if (run_dir / quark_ref).exists() else None,
                    data=None,
                )
            )
            sections.append(
                SectionV2(
                    id="quark_details",
                    title="Сведения Quark",
                    kind="json_ref",
                    summary=summary,
                    ref=quark_ref if (run_dir / quark_ref).exists() else None,
                    data={
                        "rules_total": quark_data.get("rules_total"),
                        "rules_matched": quark_data.get("rules_matched"),
                        "threat_level": quark_data.get("threat_level"),
                        "total_score": quark_data.get("total_score"),
                        "crimes": quark_data.get("crimes", []),
                    },
                )
            )

        apkid_data = stage3_data.get("apkid", {})
        apkid_ref = apkid_data.get("ref") if isinstance(apkid_data.get("ref"), str) else "tools/apkid/raw/apkid.json"
        if (run_dir / apkid_ref).exists() or apkid_data.get("present"):
            sections.append(
                SectionV2(
                    id="apkid_details",
                    title="Сведения APKiD",
                    kind="json_ref",
                    summary=f"совпадений={apkid_data.get('matches_total', 0)}",
                    ref=apkid_ref if (run_dir / apkid_ref).exists() else None,
                    data={
                        "apkid_version": apkid_data.get("apkid_version"),
                        "files_total": apkid_data.get("files_total"),
                        "matches_total": apkid_data.get("matches_total"),
                        "matches": apkid_data.get("matches", []),
                    },
                )
            )

        apkleaks_data = stage3_data.get("apkleaks", {})
        apkleaks_ref = (
            apkleaks_data.get("ref") if isinstance(apkleaks_data.get("ref"), str) else "tools/apkleaks/raw/apkleaks.json"
        )
        if (run_dir / apkleaks_ref).exists() or apkleaks_data.get("present"):
            sections.append(
                SectionV2(
                    id="apkleaks_details",
                    title="Сведения APKLeaks",
                    kind="json_ref",
                    summary=(
                        f"групп={apkleaks_data.get('groups_total', 0)}, "
                        f"утечек={apkleaks_data.get('leaks_total', 0)}"
                    ),
                    ref=apkleaks_ref if (run_dir / apkleaks_ref).exists() else None,
                    data={
                        "package": apkleaks_data.get("package"),
                        "groups": apkleaks_data.get("groups", []),
                        "entries": apkleaks_data.get("entries", []),
                    },
                )
            )

        sections.append(
            SectionV2(
                id="tools",
                title="Инструменты",
                kind="table",
                summary=f"запусков инструментов={len(tools)}",
                ref="run.json",
                data=[
                    {
                        "tool": tool.tool,
                        "status": tool.status,
                        "details": tool.details,
                    }
                    for tool in tools
                ],
            )
        )

        return sections

    def _collect_stage3_data(self, run_dir: Path, mobsf_report, quark_report) -> dict[str, dict]:
        return {
            "mobsf": self._extract_stage3_mobsf(run_dir, mobsf_report),
            "quark": self._extract_stage3_quark(run_dir, quark_report),
            "apkid": self._extract_stage3_apkid(run_dir),
            "apkleaks": self._extract_stage3_apkleaks(run_dir),
        }

    def _first_existing(self, run_dir: Path, candidates: list[str]) -> tuple[Path | None, str | None]:
        for candidate in candidates:
            path = run_dir / candidate
            if path.exists() and path.is_file():
                return path, candidate
        return None, None

    def _extract_stage3_mobsf(self, run_dir: Path, mobsf_report) -> dict:
        raw_path, raw_rel = self._first_existing(
            run_dir,
            [
                "artifacts/mobsf/static/report.json",
                "tools/mobsf/raw/report.json",
                "stage3_mobsf_report.json",
            ],
        )
        raw = _safe_json_any(raw_path) if raw_path else None
        static = getattr(mobsf_report, "static", None) if mobsf_report is not None else None

        appsec_high: list[dict] = []
        appsec_warning: list[dict] = []
        urls_top: list[str] = []
        domains_top: list[str] = []
        permissions_top: list[str] = []
        package_name = None
        version_name = None
        version_code = None
        security_score = None
        version = None
        urls_total = None
        permissions_total = None
        exported_total = None

        if static is not None:
            appsec_high = [
                {
                    "title": getattr(entry, "title", None),
                    "description": getattr(entry, "description", None),
                    "section": getattr(entry, "section", None),
                    "severity": "high",
                }
                for entry in getattr(static, "appsec_high", []) or []
                if getattr(entry, "title", None)
            ]
            appsec_warning = [
                {
                    "title": getattr(entry, "title", None),
                    "description": getattr(entry, "description", None),
                    "section": getattr(entry, "section", None),
                    "severity": "warning",
                }
                for entry in getattr(static, "appsec_warning", []) or []
                if getattr(entry, "title", None)
            ]
            urls_top = [str(value) for value in (getattr(static, "urls_top", []) or []) if str(value).strip()]
            domains_top = [str(value) for value in (getattr(static, "domains_top", []) or []) if str(value).strip()]
            permissions_top = [
                str(value) for value in (getattr(static, "permissions_top", []) or []) if str(value).strip()
            ]
            package_name = getattr(static, "package_name", None)
            version_name = getattr(static, "version_name", None)
            version_code = getattr(static, "version_code", None)
            security_score = getattr(static, "security_score", None)
            urls_total = getattr(static, "urls_total", None)
            permissions_total = getattr(static, "permissions_total", None)
            exported_total = getattr(static, "exported_total", None)

        if isinstance(raw, dict):
            package_name = raw.get("package_name") or package_name
            version_name = raw.get("version_name") or version_name
            raw_version_code = raw.get("version_code")
            if raw_version_code is not None:
                version_code = str(raw_version_code)
            version = raw.get("version") if isinstance(raw.get("version"), str) else version

            appsec = raw.get("appsec")
            if isinstance(appsec, dict):
                raw_score = appsec.get("security_score")
                if isinstance(raw_score, (int, float)):
                    security_score = int(raw_score)
                raw_high = appsec.get("high")
                if isinstance(raw_high, list):
                    appsec_high = []
                    for item in raw_high:
                        if not isinstance(item, dict):
                            continue
                        title = item.get("title")
                        if not isinstance(title, str) or not title.strip():
                            continue
                        appsec_high.append(
                            {
                                "title": title,
                                "description": item.get("description"),
                                "section": item.get("section"),
                                "severity": "high",
                            }
                        )
                raw_warning = appsec.get("warning")
                if isinstance(raw_warning, list):
                    appsec_warning = []
                    for item in raw_warning:
                        if not isinstance(item, dict):
                            continue
                        title = item.get("title")
                        if not isinstance(title, str) or not title.strip():
                            continue
                        appsec_warning.append(
                            {
                                "title": title,
                                "description": item.get("description"),
                                "section": item.get("section"),
                                "severity": "warning",
                            }
                        )

            if not urls_top:
                raw_urls = raw.get("urls")
                if isinstance(raw_urls, list):
                    seen_urls: set[str] = set()
                    for entry in raw_urls:
                        if isinstance(entry, dict):
                            nested = entry.get("urls")
                            if isinstance(nested, list):
                                for value in nested:
                                    if isinstance(value, str) and value and value not in seen_urls:
                                        seen_urls.add(value)
                        elif isinstance(entry, str) and entry and entry not in seen_urls:
                            seen_urls.add(entry)
                    urls_top = list(seen_urls)[:10]
                    urls_total = len(seen_urls)
            if not domains_top:
                raw_domains = raw.get("domains")
                if isinstance(raw_domains, dict):
                    domains_top = [str(value) for value in raw_domains.keys()][:10]
            if not permissions_top:
                raw_permissions = raw.get("permissions")
                if isinstance(raw_permissions, dict):
                    permissions_top = [str(value) for value in raw_permissions.keys()][:10]
                    permissions_total = len(raw_permissions)

            raw_exported = raw.get("exported_activities")
            if isinstance(raw_exported, list):
                exported_total = len(raw_exported)
            elif isinstance(raw.get("exported_count"), int):
                exported_total = int(raw.get("exported_count"))

        return {
            "present": mobsf_report is not None or isinstance(raw, dict),
            "ref": raw_rel or "artifacts/mobsf/static/report.json",
            "raw": raw if isinstance(raw, dict) else None,
            "version": version,
            "package_name": package_name,
            "version_name": version_name,
            "version_code": version_code,
            "security_score": int(security_score) if isinstance(security_score, (int, float)) else None,
            "urls_total": urls_total if isinstance(urls_total, (int, float)) else None,
            "permissions_total": permissions_total if isinstance(permissions_total, (int, float)) else None,
            "exported_total": exported_total if isinstance(exported_total, (int, float)) else None,
            "appsec_high": appsec_high,
            "appsec_warning": appsec_warning,
            "findings_high": len(appsec_high),
            "findings_warning": len(appsec_warning),
            "urls_top": urls_top[:10],
            "domains_top": domains_top[:10],
            "permissions_top": permissions_top[:10],
        }

    def _extract_stage3_quark(self, run_dir: Path, quark_report) -> dict:
        raw_path, raw_rel = self._first_existing(
            run_dir,
            [
                "tools/quark/quark_output.json",
                "artifacts/quark/quark_output.json",
                "stage3_quark_report.json",
            ],
        )
        raw = _safe_json_any(raw_path) if raw_path else None

        crimes: list[dict] = []
        rules_total = 0
        rules_matched = 0
        if quark_report is not None:
            summary = getattr(quark_report, "summary", None)
            if summary is not None:
                summary_total = getattr(summary, "rules_total", None)
                summary_matched = getattr(summary, "rules_matched", None)
                if isinstance(summary_total, int):
                    rules_total = summary_total
                if isinstance(summary_matched, int):
                    rules_matched = summary_matched
                for match in getattr(summary, "matches", []) or []:
                    rule_name = getattr(match, "rule_name", None) or getattr(match, "rule_path", None)
                    if not rule_name:
                        continue
                    crimes.append(
                        {
                            "rule": str(rule_name),
                            "crime": f"Matched rule: {rule_name}",
                            "label": ["rule_match"],
                        }
                    )
        if isinstance(raw, dict):
            raw_crimes = raw.get("crimes")
            if isinstance(raw_crimes, list):
                parsed: list[dict] = []
                for item in raw_crimes:
                    if not isinstance(item, dict):
                        continue
                    rule_name = item.get("rule") or item.get("rule_name")
                    crime = item.get("crime")
                    if not rule_name and not crime:
                        continue
                    parsed.append(
                        {
                            "rule": str(rule_name) if rule_name is not None else "",
                            "crime": str(crime) if crime is not None else "",
                            "label": item.get("label") if isinstance(item.get("label"), list) else [],
                            "score": item.get("score"),
                            "confidence": item.get("confidence"),
                        }
                    )
                crimes = parsed
                if rules_matched == 0:
                    from analysis.quark.runner import _quark_is_matched  # noqa: PLC0415
                    rules_matched = sum(1 for c in parsed if _quark_is_matched(c))
                if rules_total == 0:
                    rules_total = len(parsed)

        deduped_crimes: list[dict] = []
        seen: set[str] = set()
        for item in crimes:
            key = f"{item.get('rule','')}|{item.get('crime','')}"
            if key in seen:
                continue
            seen.add(key)
            deduped_crimes.append(item)

        threat_level = raw.get("threat_level") if isinstance(raw, dict) else None
        total_score = raw.get("total_score") if isinstance(raw, dict) else None
        if not rules_matched:
            from analysis.quark.runner import _quark_is_matched  # noqa: PLC0415
            rules_matched = sum(1 for c in deduped_crimes if _quark_is_matched(c))
        if not rules_total:
            rules_total = rules_matched
        return {
            "present": quark_report is not None or isinstance(raw, dict),
            "ref": raw_rel or "tools/quark/quark_output.json",
            "raw": raw if isinstance(raw, dict) else None,
            "rules_total": rules_total,
            "rules_matched": rules_matched,
            "threat_level": threat_level if isinstance(threat_level, str) else None,
            "total_score": total_score if isinstance(total_score, (int, float)) else None,
            "crimes": deduped_crimes,
        }

    def _extract_stage3_apkid(self, run_dir: Path) -> dict:
        raw_path, raw_rel = self._first_existing(
            run_dir,
            ["tools/apkid/raw/apkid.json", "stage3_apkid_report.json"],
        )
        raw = _safe_json_any(raw_path) if raw_path else None
        matches: list[dict] = []
        files_total = 0
        if isinstance(raw, dict):
            files = raw.get("files") or raw.get("file") or []
            if isinstance(files, dict):
                files = [files]
            if isinstance(files, list):
                files_total = len(files)
                for file_entry in files:
                    if not isinstance(file_entry, dict):
                        continue
                    filename = str(file_entry.get("filename") or file_entry.get("file") or "-")
                    entry_matches = file_entry.get("matches")
                    if not isinstance(entry_matches, dict):
                        continue
                    for category, values in entry_matches.items():
                        if values is None:
                            continue
                        if isinstance(values, list):
                            values_list = values
                        else:
                            values_list = [values]
                        for value in values_list:
                            if value is None or str(value).strip() == "":
                                continue
                            matches.append(
                                {
                                    "file_path": filename,
                                    "category": str(category),
                                    "value": str(value),
                                }
                            )
        return {
            "present": isinstance(raw, dict),
            "ref": raw_rel or "tools/apkid/raw/apkid.json",
            "raw": raw if isinstance(raw, dict) else None,
            "apkid_version": raw.get("apkid_version") if isinstance(raw, dict) else None,
            "files_total": files_total,
            "matches_total": len(matches),
            "matches": matches[:400],
        }

    def _extract_stage3_apkleaks(self, run_dir: Path) -> dict:
        raw_path, raw_rel = self._first_existing(
            run_dir,
            ["tools/apkleaks/raw/apkleaks.json", "stage3_apkleaks_report.json"],
        )
        raw = _safe_json_any(raw_path) if raw_path else None
        entries: list[dict] = []
        groups: list[dict] = []
        if isinstance(raw, dict):
            raw_groups = raw.get("results")
            if isinstance(raw_groups, list):
                for item in raw_groups:
                    if not isinstance(item, dict):
                        continue
                    group_name = str(item.get("name") or "unknown")
                    values = item.get("matches")
                    if not isinstance(values, list):
                        values = []
                    groups.append(
                        {
                            "name": group_name,
                            "count": len(values),
                            "examples": [str(value)[:200] for value in values[:5]],
                            "file_path": "-",
                        }
                    )
                    for value in values:
                        if value is None:
                            continue
                        text_value = str(value)
                        if not text_value.strip():
                            continue
                        entries.append(
                            {
                                "group": group_name,
                                "value": text_value,
                                "file_path": "-",
                            }
                        )
        return {
            "present": isinstance(raw, dict),
            "ref": raw_rel or "tools/apkleaks/raw/apkleaks.json",
            "raw": raw if isinstance(raw, dict) else None,
            "package": raw.get("package") if isinstance(raw, dict) else None,
            "groups_total": len(groups),
            "leaks_total": len(entries),
            "groups": groups,
            "entries": entries[:400],
        }

    def _group_findings(self, findings: list[Finding]) -> list[dict]:
        grouped: dict[str, dict] = {}
        for finding in findings:
            category = finding.category or "unknown"
            entry = grouped.setdefault(
                category,
                {
                    "category": category,
                    "count": 0,
                    "severity": "info",
                    "examples": [],
                },
            )
            entry["count"] += 1
            current = str(entry.get("severity") or "info")
            detected = _severity_hint(finding.severity)
            entry["severity"] = _max_severity([current, detected])
            evidence_value = (finding.evidence or finding.match or "").strip()
            if evidence_value and evidence_value not in entry["examples"] and len(entry["examples"]) < 5:
                entry["examples"].append(evidence_value[:180])
        ordered = sorted(
            grouped.values(),
            key=lambda item: (
                -SEVERITY_RANK.get(str(item.get("severity") or "info"), 0),
                -int(item.get("count") or 0),
                str(item.get("category") or ""),
            ),
        )
        return ordered

    def _signing_details(self, run_dir: Path, signing_summary: dict[str, int]) -> dict:
        apksigner_path = run_dir / "logs" / "apksigner.stdout.txt"
        keytool_path = run_dir / "logs" / "keytool.stdout.txt"
        apksigner_text = ""
        keytool_text = ""
        if apksigner_path.exists():
            apksigner_text = apksigner_path.read_text(encoding="utf-8", errors="replace")
        if keytool_path.exists():
            keytool_text = keytool_path.read_text(encoding="utf-8", errors="replace")

        schemes: dict[str, bool] = {}
        for scheme in ("v1", "v2", "v3", "v4"):
            pattern = re.compile(
                rf"verified using (?:apk signature scheme )?{scheme}[^:]*:\s*(true|false)",
                re.IGNORECASE,
            )
            match = pattern.search(apksigner_text)
            if match:
                schemes[scheme] = match.group(1).lower() == "true"

        cert_info: dict[str, str] = {}
        patterns = {
            "subject_dn": r"^\s*Owner:\s*(.+)$",
            "issuer_dn": r"^\s*Issuer:\s*(.+)$",
            "serial_number": r"^\s*Serial number:\s*(.+)$",
            "validity": r"^\s*Valid from:\s*(.+)$",
            "signature_algorithm": r"^\s*Signature algorithm name:\s*(.+)$",
            "sha1": r"^\s*SHA1:\s*(.+)$",
            "sha256": r"^\s*SHA256:\s*(.+)$",
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, keytool_text, flags=re.MULTILINE)
            if match:
                cert_info[key] = match.group(1).strip()

        return {
            "schemes": schemes,
            "certificate": cert_info,
            "issues": signing_summary,
            "issues_total": sum(signing_summary.values()),
            "refs": {
                "apksigner": "logs/apksigner.stdout.txt" if apksigner_path.exists() else None,
                "keytool": "logs/keytool.stdout.txt" if keytool_path.exists() else None,
            },
        }

    def _native_strings_summary(self, run_dir: Path) -> dict:
        hits_path = run_dir / "artifacts" / "strings_so_rg_hits.txt"
        so_root = run_dir / "artifacts" / "out_apktool"
        so_files = 0
        if so_root.exists():
            try:
                so_files = sum(1 for _ in so_root.rglob("*.so"))
            except OSError:
                so_files = 0

        hits: list[str] = []
        if hits_path.exists():
            try:
                hits = [line.strip() for line in hits_path.read_text(encoding="utf-8", errors="replace").splitlines()]
            except OSError:
                hits = []
        hits = [line for line in hits if line]
        return {
            "so_files": so_files,
            "hits_total": len(hits),
            "top_hits": hits[:10],
            "ref": "artifacts/strings_so_rg_hits.txt" if hits_path.exists() else None,
        }

    def _derive_report_status(self, run_status: ReportStatusV2, tools: list[ToolRunV2]) -> ReportStatusV2:
        if run_status == "not_implemented":
            return "not_implemented"
        if run_status == "fail":
            return "fail"
        statuses = {tool.status for tool in tools}
        if "fail" in statuses:
            return "partial" if "ok" in statuses else "fail"
        if "partial" in statuses or "skipped" in statuses:
            return "partial"
        return run_status

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
                            is_exported = has_intent and tag in (
                                "activity",
                                "activity-alias",
                                "service",
                                "receiver",
                            )
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
        url_map, ip_map = _collect_endpoints(findings)
        return {"urls": len(url_map), "ips": len(ip_map)}

    def _signing_summary(self, findings: list[Finding]) -> dict[str, int]:
        summary: dict[str, int] = {}
        for finding in findings:
            if not finding.category.startswith("supplychain_"):
                continue
            summary[finding.category] = summary.get(finding.category, 0) + 1
        return summary

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

    def _parse_jadx_errors_for_output(self, stdout_path: Path, stderr_path: Path) -> int:
        for path in (stdout_path, stderr_path):
            if not path.exists() or not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            match = re.search(r"errors, count:\s*(\d+)", text)
            if match:
                return int(match.group(1))
        return 0

    def _parse_yara_matches_for_output(self, stdout_path: Path) -> tuple[int, int]:
        if not stdout_path.exists() or not stdout_path.is_file():
            return 0, 0
        try:
            lines = [line for line in stdout_path.read_text(encoding="utf-8", errors="replace").splitlines() if line]
        except OSError:
            return 0, 0
        rules = {line.split()[0] for line in lines if line.split()}
        return len(lines), len(rules)

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

    def _collect_artifacts(self, run_dir: Path, stage: str) -> list[ArtifactRefV2]:
        collected: dict[str, Path] = {}

        def add_path(path: Path) -> None:
            if not path.exists():
                return
            rel = _relpath(run_dir, path)
            if rel in collected:
                return
            collected[rel] = path

        add_path(run_dir / "run.json")

        logs_dir = run_dir / "logs"
        if logs_dir.exists():
            for path in sorted(logs_dir.glob("*.txt")):
                add_path(path)

        artifacts_dir = run_dir / "artifacts"
        if artifacts_dir.exists():
            for path in sorted(artifacts_dir.iterdir()):
                add_path(path)
                if stage == STAGE_CROSS_TOOL and path.is_dir():
                    for nested in sorted(path.rglob("*")):
                        if nested.is_file():
                            add_path(nested)

        if stage == STAGE_STATIC:
            for folder in ("out_apktool", "out_jadx", "certs"):
                folder_path = artifacts_dir / folder
                if folder_path.exists():
                    add_path(folder_path)
            manifest_path = artifacts_dir / "out_apktool" / "AndroidManifest.xml"
            if manifest_path.exists():
                add_path(manifest_path)

        if stage == STAGE_CROSS_TOOL:
            normalized = run_dir / "normalized" / "indicators.json"
            add_path(normalized)
            tools_dir = run_dir / "tools"
            if tools_dir.exists():
                for tool_path in sorted(path for path in tools_dir.iterdir() if path.is_dir()):
                    add_path(tool_path)
                    for nested in sorted(tool_path.rglob("*")):
                        if nested.is_file():
                            add_path(nested)

        if stage == STAGE_DYNAMIC:
            tools_dir = run_dir / "tools"
            if tools_dir.exists():
                for tool_path in sorted(path for path in tools_dir.iterdir() if path.is_dir()):
                    add_path(tool_path)
                    for nested in sorted(tool_path.rglob("*")):
                        if nested.is_file():
                            add_path(nested)
            diffs_dir = run_dir / "diffs"
            if diffs_dir.exists():
                for path in sorted(diffs_dir.iterdir()):
                    add_path(path)
            artifacts_subdir = run_dir / "artifacts"
            if artifacts_subdir.exists():
                for path in sorted(artifacts_subdir.rglob("*")):
                    if path.is_file():
                        add_path(path)

        refs: list[ArtifactRefV2] = []
        for rel in sorted(collected):
            path = collected[rel]
            if path.is_dir():
                refs.append(
                    ArtifactRefV2(
                        id=_hash_id("art", rel),
                        kind="dir",
                        name=path.name,
                        path=rel,
                        sha256=None,
                        size=None,
                        mime="inode/directory",
                    )
                )
                continue

            mime, _ = mimetypes.guess_type(path.name)
            if path.suffix == ".json" and not mime:
                mime = "application/json"
            if path.suffix == ".html" and not mime:
                mime = "text/html"
            try:
                size = path.stat().st_size
            except OSError:
                size = None
            try:
                digest = sha256_file(path)
            except OSError:
                digest = None
            refs.append(
                ArtifactRefV2(
                    id=_hash_id("art", rel),
                    kind="file",
                    name=path.name,
                    path=rel,
                    sha256=digest,
                    size=size,
                    mime=mime or "application/octet-stream",
                )
            )

        return refs
