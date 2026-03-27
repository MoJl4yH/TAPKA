"""Semgrep runner — запускает Android/Java-правила на выводе JADX."""
from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from analysis.settings import SETTINGS_DIR

# Локальные правила mindedsecurity — хранятся в ~/.tapka/semgrep-rules/mindedsecurity
# (аналогично quark-rules, клонируются setup.sh)
MINDEDSECURITY_RULES = SETTINGS_DIR / "semgrep-rules" / "mindedsecurity" / "rules"

# Поддиректории mindedsecurity с неподдерживаемыми rule-типами (join rules, semgrep>=1.x)
# arch/ содержит только mstg-arch-9.yaml с mode:join → AttributeError в semgrep 1.156
_MINDEDSECURITY_SKIP_DIRS: set[str] = {"arch", "resilience"}

# Локальные копии registry-правил — скачиваются setup.sh, хранятся офлайн
# Соответствие: r/java.android.security → java-android-security.yaml
_REGISTRY_DIR = SETTINGS_DIR / "semgrep-rules" / "registry"
_REGISTRY_FILES: list[tuple[str, Path]] = [
    ("java-android-security",    _REGISTRY_DIR / "java-android-security.yaml"),
    ("java-lang-security-audit", _REGISTRY_DIR / "java-lang-security-audit.yaml"),
    ("generic-secrets-gitleaks", _REGISTRY_DIR / "generic-secrets-gitleaks.yaml"),
]

# Список существующих локальных registry-рулсетов (пустой = ни один не скачан)
ANDROID_RULESETS: list[str] = [str(p) for _, p in _REGISTRY_FILES if p.exists()]

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

# Маппинг rule_id → category (case-insensitive lookup via .lower())
RULE_TO_CATEGORY: dict[str, str] = {
    # ── Semgrep registry rules ───────────────────────────────────────────────
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
    "java.android.security.exported_activity": "vul_exported_component_no_permission",
    "java.lang.security.audit.formatted-sql-string": "sec_sql_injection",
    "java.lang.security.audit.unsafe-reflection": "ndv_reflection_heavy",
    "generic.secrets.gitleaks.generic-api-key": "secret_hardcoded_token_or_apikey",
    "generic.secrets.gitleaks.private-key": "secret_private_key_pem",
    "generic.secrets.gitleaks.jwt": "secret_jwt_embedded",
    # ── MindedSecurity MSTG rules (IDs нормализованы к lowercase) ──────────
    "mstg-storage-2": "sec_external_storage_sensitive",
    "mstg-storage-3": "sec_log_sensitive_data",
    "mstg-storage-5": "sec_sharedprefs_sensitive",
    "mstg-storage-14": "sec_world_readable_writable",
    "mstg-crypto-1": "sec_weak_crypto",
    "mstg-crypto-2": "sec_hardcoded_crypto_key",
    "mstg-crypto-3": "sec_static_iv",
    "mstg-network-1": "sec_cleartext_traffic_allowed",
    "mstg-network-3": "sec_tls_trust_all",
    "mstg-network-4": "sec_hostname_verifier_bypass",
    "mstg-network-6": "sec_custom_ca_store_or_user_certs",
    "mstg-platform-2": "sec_intent_injection_in_exported",
    "mstg-platform-5": "sec_insecure_webview_bridge",
    "mstg-platform-6": "sec_insecure_webview_file_access",
    "mstg-platform-7": "sec_webview_js_enabled",
}

# Severity из semgrep → наши уровни
SEMGREP_SEVERITY_MAP: dict[str, str] = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}

_SEMGREP_TIMEOUT_SEC = 300

# -j: степень параллелизма. None = полагаемся на semgrep default (7).
# Явно задаём max(1, cpu_count - 1) чтобы не перегружать GUI-поток.
import os as _os
_SEMGREP_JOBS: int = max(1, (_os.cpu_count() or 4) - 1)


def _find_semgrep() -> str | None:
    """Находит semgrep-бинарь, предпочитая системную установку вне venv.

    В GUI-контексте процесс запускается из venv, и PATH ставит .venv/bin первым.
    Venv-версия semgrep использует pysemgrep как fallback (зависит от pkg_resources),
    тогда как системная (~/.local/bin/semgrep) работает стабильно.
    """
    import shutil
    import sys
    import os

    # Collect all semgrep candidates in PATH order
    candidates: list[str] = []
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    for d in path_dirs:
        p = os.path.join(d, "semgrep")
        if os.path.isfile(p) and os.access(p, os.X_OK):
            candidates.append(p)

    if not candidates:
        return None

    # Prefer any candidate outside the current Python venv
    venv_prefix = getattr(sys, "prefix", "")
    base_prefix = getattr(sys, "base_prefix", venv_prefix)
    in_venv = venv_prefix != base_prefix

    if in_venv:
        for c in candidates:
            if not c.startswith(venv_prefix):
                return c  # first non-venv semgrep wins

    # Fall back to first found (may be venv semgrep)
    return candidates[0]


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

    Запускает два отдельных прогона:
    1. Registry-правила (всегда)
    2. MindedSecurity-правила (если установлены; ошибка не блокирует registry-результаты)
    """
    log = on_progress or (lambda m: None)

    if not jadx_src_dir.exists():
        log(f"[semgrep] SKIP: jadx не найден: {jadx_src_dir}")
        return []

    import shutil
    semgrep_bin = _find_semgrep()
    if not semgrep_bin:
        log("[semgrep] SKIP: semgrep не найден в PATH")
        return []
    log(f"[semgrep] binary: {semgrep_bin}")

    output_dir.mkdir(parents=True, exist_ok=True)
    jadx_abs = jadx_src_dir.resolve()

    all_raw_results: list[dict] = []

    # ── Прогон 1: registry + extra правила ──────────────────────────────────
    registry_rulesets = (extra_rules or []) + ANDROID_RULESETS
    registry_json = output_dir / "semgrep_registry.json"
    log(f"[semgrep] Registry-прогон (timeout={_SEMGREP_TIMEOUT_SEC}s)…")
    t0 = time.monotonic()
    registry_raw = _run_semgrep_once(
        rulesets=registry_rulesets,
        jadx_abs=jadx_abs,
        output_json=registry_json,
        cwd=None,
        log=log,
        label="registry",
        semgrep_bin=semgrep_bin,
    )
    log(f"[semgrep] Registry: {len(registry_raw)} совпадений за {round(time.monotonic()-t0,1)}s")
    all_raw_results.extend(registry_raw)

    # ── Прогон 2: MindedSecurity (опционально) ───────────────────────────────
    use_mindedsecurity = MINDEDSECURITY_RULES.is_dir()
    if use_mindedsecurity:
        # Передаём поддиректории по отдельности, пропуская проблемные (join rules)
        ms_subdirs = [
            str(d) for d in sorted(MINDEDSECURITY_RULES.iterdir())
            if d.is_dir() and d.name not in _MINDEDSECURITY_SKIP_DIRS
        ]
        if ms_subdirs:
            ms_json = output_dir / "semgrep_mindedsecurity.json"
            # cwd = корень репо mindedsecurity, чтобы .semgrepignore подхватился
            ms_cwd = MINDEDSECURITY_RULES.parent.parent
            log(f"[semgrep] MindedSecurity-прогон ({len(ms_subdirs)} dirs, timeout={_SEMGREP_TIMEOUT_SEC}s)…")
            t1 = time.monotonic()
            ms_raw = _run_semgrep_once(
                rulesets=ms_subdirs,
                jadx_abs=jadx_abs,
                output_json=ms_json,
                cwd=ms_cwd,
                log=log,
                label="mindedsecurity",
                semgrep_bin=semgrep_bin,
            )
            log(f"[semgrep] MindedSecurity: {len(ms_raw)} совпадений за {round(time.monotonic()-t1,1)}s")
            all_raw_results.extend(ms_raw)

    findings = _parse_raw_results(all_raw_results)
    log(f"[semgrep] Итого найдено {len(findings)} совпадений")
    return findings


def _run_semgrep_once(
    rulesets: list[str],
    jadx_abs: Path,
    output_json: Path,
    cwd: Path | None,
    log: Callable[[str], None],
    label: str,
    semgrep_bin: str = "semgrep",
) -> list[dict]:
    """Запускает один прогон semgrep и возвращает сырые результаты (list of result dicts).

    При ошибке логирует и возвращает [].
    """
    # Write stdout to file (avoids Qt pipe-capture issues).
    # Use explicit semgrep_bin path so system semgrep is preferred over venv wrapper.
    cmd: list[str] = [semgrep_bin, "--json", "-j", str(_SEMGREP_JOBS)]
    for ruleset in rulesets:
        cmd += ["--config", ruleset]
    for excl in LIBRARY_EXCLUDES:
        cmd += ["--exclude", excl]
    cmd.append(str(jadx_abs))

    _log_file = output_json.parent / f"{label}.log"

    def _flog(msg: str) -> None:
        log(msg)
        try:
            with _log_file.open("a", encoding="utf-8") as _f:
                _f.write(msg + "\n")
        except Exception:
            pass

    # Write stdout directly to output_json file (avoids Qt pipe-capture issues).
    # Open in binary + unbuffered mode to avoid Python buffer interfering with child writes.
    # stderr captured via PIPE for logging only.
    try:
        _flog(f"cmd: {' '.join(cmd[:6])} ...")
        with output_json.open("wb", buffering=0) as _stdout_f:
            proc = subprocess.run(
                cmd,
                stdout=_stdout_f,
                stderr=subprocess.PIPE,
                timeout=_SEMGREP_TIMEOUT_SEC,
                cwd=str(cwd) if cwd else None,
            )
        _size = output_json.stat().st_size if output_json.exists() else 0
        _stderr_text = (proc.stderr or b"").decode("utf-8", errors="replace") if isinstance(proc.stderr, bytes) else (proc.stderr or "")
        _flog(f"rc={proc.returncode} output_size={_size}")
        if _stderr_text:
            _flog(f"stderr[:3000]={_stderr_text[:3000]}")
        if proc.returncode not in (0, 1, 2):
            _flog(f"[semgrep:{label}] Ошибка rc={proc.returncode}")
            return []
        if proc.returncode == 2 and _size < 10:
            _flog(f"[semgrep:{label}] Аварийное завершение rc=2")
            return []
    except subprocess.TimeoutExpired:
        _flog(f"[semgrep:{label}] Таймаут {_SEMGREP_TIMEOUT_SEC}s")
        return []
    except OSError as exc:
        _flog(f"[semgrep:{label}] Не удалось запустить: {exc}")
        return []

    if not output_json.exists() or output_json.stat().st_size < 10:
        _flog(f"[semgrep:{label}] Пустой результат")
        return []

    try:
        raw = json.loads(output_json.read_text(encoding="utf-8"))
        return raw.get("results", [])
    except (json.JSONDecodeError, OSError) as exc:
        log(f"[semgrep:{label}] Не удалось прочитать JSON: {exc}")
        return []


def _parse_raw_results(raw_results: list[dict]) -> list[SemgrepFinding]:
    """Преобразует сырые semgrep-результаты в список :class:`SemgrepFinding`."""
    findings: list[SemgrepFinding] = []
    for result in raw_results:
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
    return findings


def _rule_to_category(rule_id: str) -> str:
    """Переводит semgrep rule_id в TAPKA-категорию (case-insensitive).

    Обрабатывает versioned IDs (MSTG-STORAGE-5.1 → mstg-storage-5) и
    префиксы инструментов (mindedsecurity.rules.storage.MSTG-STORAGE-5).
    """
    import re as _re
    rule_lower = rule_id.lower()
    # Точное совпадение (нормализовано к lowercase)
    if rule_lower in RULE_TO_CATEGORY:
        return RULE_TO_CATEGORY[rule_lower]
    # Суффиксное или префиксное совпадение
    # Обрабатывает: org-prefix (mindedsecurity.rules.X.KEY) и
    # дублированный суффикс (java.android.security.KEY.KEY)
    for key, cat in RULE_TO_CATEGORY.items():
        if rule_lower.endswith(key):
            return cat
        if rule_lower.startswith(key + ".") or rule_lower == key:
            return cat
    # Суффиксное совпадение без версионного суффикса (MSTG-STORAGE-5.1 → MSTG-STORAGE-5)
    rule_no_ver = _re.sub(r'\.\d+$', '', rule_lower)
    if rule_no_ver != rule_lower:
        if rule_no_ver in RULE_TO_CATEGORY:
            return RULE_TO_CATEGORY[rule_no_ver]
        for key, cat in RULE_TO_CATEGORY.items():
            if rule_no_ver.endswith(key):
                return cat
    # Эвристика по ключевым словам rule_id
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
