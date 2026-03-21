"""Semgrep runner — запускает Android/Java-правила на выводе JADX."""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ANDROID_RULESETS: list[str] = [
    "p/android-security",
    "p/java-security",
    "p/gitleaks",
]

# Библиотечные пакеты — исключаем, чтобы не было ложных срабатываний
LIBRARY_EXCLUDES: list[str] = [
    "android/",
    "androidx/",
    "com/google/android/gms/",
    "com/google/firebase/",
    "com/squareup/",
    "okhttp3/",
    "retrofit2/",
    "kotlinx/",
    "kotlin/",
    "org/bouncycastle/",
    "io/flutter/",
    "com/facebook/",
]

# Маппинг rule_id → category (расширяемый)
RULE_TO_CATEGORY: dict[str, str] = {
    "java.android.security.tls-unverified": "sec_tls_trust_all",
    "java.android.security.webview-js-enabled": "sec_webview_js_enabled",
    "java.android.security.webview-addjavascriptinterface": "sec_insecure_webview_bridge",
    "java.android.security.insecure-trust-manager": "sec_tls_trust_all",
    "java.android.security.ssl-hostname-not-verified": "sec_hostname_verifier_bypass",
    "java.android.security.use-of-broken-or-risky-cryptographic-algorithm": "sec_weak_crypto",
    "java.android.security.ecb-cipher": "sec_weak_crypto",
    "java.android.security.hardcoded-password-field": "secret_hardcoded_credentials",
    "java.android.security.hardcoded-generic-secret": "secret_hardcoded_credentials",
    "java.android.security.predictable-seed-securerandom": "sec_predictable_random",
    "java.android.security.implicit-pending-intent": "vul_pendingintent_mutable",
    "java.android.security.sql-injection-sqllite": "sec_sql_injection",
    "java.lang.security.audit.formatted-sql-string": "sec_sql_injection",
    "generic.secrets.gitleaks.generic-api-key": "secret_hardcoded_token_or_apikey",
    "generic.secrets.gitleaks.private-key": "secret_private_key_pem",
    "generic.secrets.gitleaks.jwt": "secret_jwt_embedded",
}

# Severity из semgrep → наши уровни
SEMGREP_SEVERITY_MAP: dict[str, str] = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


@dataclass
class SemgrepFinding:
    rule_id: str
    category: str
    severity: str
    file: str
    line: int
    message: str
    snippet: str | None = None


def run_semgrep(
    jadx_src_dir: Path,
    output_dir: Path,
    on_progress: Callable[[str], None] | None = None,
    extra_rules: list[str] | None = None,
) -> list[SemgrepFinding]:
    """Запускает semgrep на директории с JADX-декомпилированным кодом.

    Возвращает список :class:`SemgrepFinding`.
    Если semgrep не установлен или директория не существует — возвращает [].
    """
    log = on_progress or (lambda m: None)

    if not jadx_src_dir.exists():
        log(f"[semgrep] Директория JADX не найдена: {jadx_src_dir}")
        return []

    import shutil
    if not shutil.which("semgrep"):
        log("[semgrep] semgrep не найден в PATH — пропускаем")
        return []

    output_dir.mkdir(parents=True, exist_ok=True)
    output_json = output_dir / "semgrep_results.json"

    rulesets = (extra_rules or []) + ANDROID_RULESETS

    cmd: list[str] = ["semgrep", "--json", "--output", str(output_json)]
    for ruleset in rulesets:
        cmd += ["--config", ruleset]
    for excl in LIBRARY_EXCLUDES:
        cmd += ["--exclude", excl]
    cmd.append(str(jadx_src_dir))

    log(f"[semgrep] Запуск: {' '.join(cmd[:6])} ... {jadx_src_dir.name}")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=None,
        )
        if proc.returncode not in (0, 1):  # semgrep exits 1 when findings found
            log(f"[semgrep] Ошибка (rc={proc.returncode}): {proc.stderr[:300]}")
            return []
    except (subprocess.TimeoutExpired, OSError) as exc:
        log(f"[semgrep] Исключение при запуске: {exc}")
        return []

    if not output_json.exists():
        log("[semgrep] Результирующий JSON не найден")
        return []

    try:
        raw = json.loads(output_json.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        log(f"[semgrep] Не удалось прочитать JSON: {exc}")
        return []

    findings: list[SemgrepFinding] = []
    for result in raw.get("results", []):
        rule_id = str(result.get("check_id") or "")
        semgrep_sev = str(result.get("extra", {}).get("severity") or "INFO").upper()
        severity = SEMGREP_SEVERITY_MAP.get(semgrep_sev, "low")
        category = _rule_to_category(rule_id)
        path_info = result.get("path", "")
        start = result.get("start") or {}
        line = int(start.get("line") or 0)
        message = str(result.get("extra", {}).get("message") or "")[:500]
        lines_snippet = result.get("extra", {}).get("lines")
        snippet = str(lines_snippet)[:300] if lines_snippet else None

        findings.append(
            SemgrepFinding(
                rule_id=rule_id,
                category=category,
                severity=severity,
                file=path_info,
                line=line,
                message=message,
                snippet=snippet,
            )
        )

    log(f"[semgrep] Найдено {len(findings)} совпадений")
    return findings


def _rule_to_category(rule_id: str) -> str:
    """Переводит semgrep rule_id в TAPKA-категорию."""
    # Точное совпадение
    if rule_id in RULE_TO_CATEGORY:
        return RULE_TO_CATEGORY[rule_id]
    # Суффиксное совпадение (убираем org-prefix)
    for key, cat in RULE_TO_CATEGORY.items():
        if rule_id.endswith(key):
            return cat
    # Эвристика по ключевым словам rule_id
    rule_lower = rule_id.lower()
    if "hardcoded" in rule_lower and ("password" in rule_lower or "secret" in rule_lower or "key" in rule_lower):
        return "secret_hardcoded_credentials"
    if "sql" in rule_lower:
        return "sec_sql_injection"
    if "tls" in rule_lower or "ssl" in rule_lower or "trust" in rule_lower:
        return "sec_tls_trust_all"
    if "webview" in rule_lower:
        return "sec_insecure_webview_bridge"
    if "crypto" in rule_lower or "cipher" in rule_lower:
        return "sec_weak_crypto"
    if "private-key" in rule_lower or "private_key" in rule_lower:
        return "secret_private_key_pem"
    if "api-key" in rule_lower or "api_key" in rule_lower or "apikey" in rule_lower:
        return "secret_hardcoded_token_or_apikey"
    if "jwt" in rule_lower:
        return "secret_jwt_embedded"
    return "sec_semgrep_generic"
