#!/usr/bin/env python3
"""TAPKA CLI — запуск анализа APK из командной строки.

Использование:
    python tapka_cli.py path/to/app.apk --stage1
    python tapka_cli.py path/to/app.apk --stage1 --stage2 --stage3
    python tapka_cli.py path/to/app.apk --all
    python tapka_cli.py path/to/app.apk --stage3 --no-quark

Опции:
    APK_PATH            Путь до APK-файла (обязательный аргумент)
    --all               Запустить все стадии (Stage1 + Stage2 + Stage3)
    --stage1            Статический анализ (jadx, YARA, rg, apktool, keytool)
    --stage2            Динамический анализ (эмулятор, ADB, pcap, filesystem diff)
    --stage3            Кросс-инструментальный анализ (MobSF, Quark, APKiD, APKLeaks)
    --workspace DIR     Рабочая область (по умолчанию: из настроек или ~/tapka_workspace)
    --avd NAME          AVD для Stage 2 (по умолчанию: tapka_api30)
    --runtime SEC       Длительность capture в Stage 2, секунды (по умолчанию: 60)
    --mobsf-url URL     URL MobSF (по умолчанию: http://127.0.0.1:8000)
    --no-mobsf          Пропустить MobSF в Stage 3
    --no-quark          Пропустить Quark в Stage 3
    --no-apkid          Пропустить APKiD в Stage 3
    --no-apkleaks       Пропустить APKLeaks в Stage 3
    --mitm-intercept    Включить mitmproxy HTTPS-перехват в Stage 2
    --mitm-port PORT    Порт mitmproxy (по умолчанию: 8888)
    --no-timeout        Отключить таймаут (по умолч. 300 с) для тяжёлых инструментов
    --report-type       Тип итогового отчёта: standard (по умолчанию) или extended
    --output FILE       Путь для сохранения итогового JSON-отчёта
"""

from __future__ import annotations

import argparse
import sys
import time
import traceback
from pathlib import Path

# Добавляем корень проекта в sys.path, чтобы CLI работал из любой директории.
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from analysis.mobsf import DEFAULT_MOBSF_URL, normalize_base_url  # noqa: E402
from analysis.mobsf.stage3_runner import Stage3Config  # noqa: E402
from analysis.models.stage2 import Stage2Config  # noqa: E402
from analysis.settings import (  # noqa: E402
    DEFAULT_WORKSPACE,
    get_mobsf_api_key,
    load_settings,
    save_settings,
    set_mobsf_api_key,
)
from analysis.stage1_analysis import Stage1StaticRunner  # noqa: E402
from analysis.stage2.runner import Stage2DynamicRunner  # noqa: E402
from analysis.stage3_batch_runner import Stage3BatchConfig, Stage3BatchRunner  # noqa: E402
from analysis.apkid.stage3_runner import Stage3ApkidConfig  # noqa: E402
from analysis.apkleaks.stage3_runner import Stage3ApkleaksConfig  # noqa: E402
from analysis.quark.stage3_runner import Stage3QuarkConfig  # noqa: E402
from analysis.storage import Storage  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# Форматирование
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    minutes, secs = divmod(seconds, 60)
    if minutes:
        return f"{minutes} мин {secs} с"
    return f"{secs} с"


def _section(title: str) -> None:
    bar = "─" * 60
    print(f"\n{bar}", flush=True)
    print(f"  {title}", flush=True)
    print(bar, flush=True)


def _info(msg: str) -> None:
    print(f"[tapka] {msg}", flush=True)


def _ok(msg: str) -> None:
    print(f"[tapka] ✓ {msg}", flush=True)


def _err(msg: str) -> None:
    print(f"[tapka] ✗ {msg}", file=sys.stderr, flush=True)


# ─────────────────────────────────────────────────────────────────────────────
# Callbacks прогресса — воспроизводят лог GUI в stdout
# ─────────────────────────────────────────────────────────────────────────────

def _stage1_progress(payload: dict | object) -> None:
    """Stage1 передаёт dict с полями message/completed/total/elapsed_sec/eta_sec."""
    if isinstance(payload, dict):
        msg = payload.get("message", "")
        completed = int(payload.get("completed", 0))
        total = int(payload.get("total", 0))
        elapsed = payload.get("elapsed_sec")
        eta = payload.get("eta_sec")

        parts: list[str] = []
        if msg:
            parts.append(msg)
        if total:
            parts.append(f"{completed}/{total}")
        if elapsed is not None:
            parts.append(f"Прошло {_fmt_duration(elapsed)}")
        if eta is not None:
            parts.append(f"Осталось ~{_fmt_duration(eta)}")
        print("  " + " · ".join(parts), flush=True)
    else:
        print(f"  {payload}", flush=True)


def _str_progress(msg: str) -> None:
    """Stage2/3 передают строки вида '[HH:MM:SS] текст' из build_stage3_logger."""
    print(f"  {msg}", flush=True)


# ─────────────────────────────────────────────────────────────────────────────
# Запуск стадий
# ─────────────────────────────────────────────────────────────────────────────

def _count_findings(run_dir: Path) -> int:
    """Считает количество находок из findings.json в run_dir."""
    import json as _json
    findings_file = run_dir / "findings" / "findings.json"
    if not findings_file.exists():
        return 0
    try:
        data = _json.loads(findings_file.read_text(encoding="utf-8"))
        return len(data) if isinstance(data, list) else 0
    except (OSError, ValueError):
        return 0


def run_stage1(storage: Storage, project_id: str) -> bool:
    _section("ЭТАП 1 — Статический анализ")
    start = time.monotonic()
    try:
        runner = Stage1StaticRunner(storage, on_progress=_stage1_progress)
        run = runner.run(project_id)
        elapsed = time.monotonic() - start
        run_dir = storage.get_run_dir(project_id, run.run_id)
        findings_count = _count_findings(run_dir)
        _ok(f"Этап 1 завершён за {_fmt_duration(elapsed)}.")
        _info(f"Найдено: {findings_count} находок   Статус: {run.status}")
        _info(f"Run dir: {run_dir}")
        return True
    except Exception:  # pylint: disable=broad-exception-caught
        _err("Этап 1 завершился ошибкой:")
        traceback.print_exc(file=sys.stderr)
        return False


def run_stage2(storage: Storage, project_id: str, config: Stage2Config) -> bool:
    _section("ЭТАП 2 — Динамический анализ")
    start = time.monotonic()
    try:
        runner = Stage2DynamicRunner(storage, config=config, on_progress=_str_progress)
        run = runner.run(project_id)
        elapsed = time.monotonic() - start
        _ok(f"Этап 2 завершён за {_fmt_duration(elapsed)}.")
        _info(f"Статус: {run.status}")
        run_dir = storage.get_run_dir(project_id, run.run_id)
        _info(f"Run dir: {run_dir}")
        return True
    except Exception:  # pylint: disable=broad-exception-caught
        _err("Этап 2 завершился ошибкой:")
        traceback.print_exc(file=sys.stderr)
        return False


def run_stage3(storage: Storage, project_id: str, config: Stage3BatchConfig) -> bool:
    _section("ЭТАП 3 — Кросс-инструментальный анализ")
    start = time.monotonic()
    try:
        runner = Stage3BatchRunner(storage, config=config, on_progress=_str_progress)
        results = runner.run(project_id)
        elapsed = time.monotonic() - start
        _ok(f"Этап 3 завершён за {_fmt_duration(elapsed)}.")
        errors = []
        for tool, result in results.items():
            if isinstance(result, Exception):
                _info(f"  {tool}: ОШИБКА — {result}")
                errors.append(tool)
            else:
                _info(f"  {tool}: OK")
        if errors:
            _err(f"Ошибки в инструментах: {', '.join(errors)}")
        return not errors
    except Exception:  # pylint: disable=broad-exception-caught
        _err("Этап 3 завершился ошибкой:")
        traceback.print_exc(file=sys.stderr)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tapka",
        description="TAPKA — анализ APK на уязвимости (статический / динамический / кросс-инструментальный)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("apk", metavar="APK_PATH", help="Путь до APK-файла")

    stages = parser.add_argument_group("Стадии анализа")
    stages.add_argument("--all", action="store_true", help="Запустить все стадии: Stage1 → Stage2 → Stage3")
    stages.add_argument("--stage1", action="store_true", help="Статический анализ (jadx, YARA, rg, apktool)")
    stages.add_argument("--stage2", action="store_true", help="Динамический анализ (эмулятор + ADB)")
    stages.add_argument("--stage3", action="store_true", help="Кросс-инструментальный анализ (MobSF, Quark, APKiD, APKLeaks)")

    workspace = parser.add_argument_group("Рабочая область")
    workspace.add_argument(
        "--workspace",
        metavar="DIR",
        help=f"Путь до рабочей области (по умолчанию: из настроек или {DEFAULT_WORKSPACE})",
    )

    s2 = parser.add_argument_group("Опции Stage 2")
    s2.add_argument("--avd", metavar="NAME", default="tapka_api30",
                    help="Имя AVD для эмулятора (по умолчанию: tapka_api30)")
    s2.add_argument("--runtime", metavar="SEC", type=int, default=180,
                    help="Длительность перехвата трафика, секунды (по умолчанию: 180)")
    s2.add_argument("--mitm-intercept", action="store_true",
                    help="Включить mitmproxy HTTPS-перехват в Stage 2 (требует: pip install mitmproxy). "
                         "Требует эмулятор с флагом -writable-system. "
                         "Пример: emulator @<avd> -writable-system")
    s2.add_argument("--mitm-port", metavar="PORT", type=int, default=8888,
                    help="Порт mitmproxy (по умолчанию: 8888)")

    s3 = parser.add_argument_group("Опции Stage 3")
    s3.add_argument("--mobsf-url", metavar="URL",
                    help=f"URL MobSF (по умолчанию: {DEFAULT_MOBSF_URL})")
    s3.add_argument("--no-mobsf", action="store_true", help="Пропустить MobSF")
    s3.add_argument("--no-quark", action="store_true", help="Пропустить Quark")
    s3.add_argument("--no-apkid", action="store_true", help="Пропустить APKiD")
    s3.add_argument("--no-apkleaks", action="store_true", help="Пропустить APKLeaks")
    s3.add_argument("--no-timeout", action="store_true",
                    help="Отключить таймаут (по умолчанию 300 с) для APKiD и APKLeaks")
    s3.add_argument("--mobsf-dynamic", action="store_true",
                    help="Запустить динамический анализ MobSF")
    s3.add_argument("--mobsf-frida", action="store_true",
                    help="Включить Frida инструментирование в MobSF dynamic")
    s3.add_argument("--mobsf-tls-tests", action="store_true",
                    help="Запустить TLS тестирование в MobSF dynamic")
    s3.add_argument("--mobsf-dynamic-v2", action="store_true",
                    help="Использовать улучшенный MobSF dynamic workflow (mobsfy + CA + proxy + wait)")

    report = parser.add_argument_group("Отчёт")
    report.add_argument("--report-type", choices=["standard", "extended"], default="standard",
                        help="Тип итогового отчёта (по умолчанию: standard)")
    report.add_argument("--output", metavar="FILE",
                        help="Путь для сохранения итогового JSON-отчёта")

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.all:
        args.stage1 = args.stage2 = args.stage3 = True

    if not (args.stage1 or args.stage2 or args.stage3):
        parser.error("Укажите хотя бы одну стадию: --stage1 --stage2 --stage3 или --all")

    # Проверяем APK
    apk_path = Path(args.apk).resolve()
    if not apk_path.is_file():
        _err(f"APK-файл не найден: {apk_path}")
        return 1
    if apk_path.suffix.lower() != ".apk":
        _err(f"Файл не является APK: {apk_path}")
        return 1

    # Рабочая область
    settings = load_settings()
    workspace = args.workspace or settings.get("workspace") or DEFAULT_WORKSPACE
    workspace = str(Path(workspace).expanduser().resolve())

    # Если --mobsf-url передан, сохраняем в настройки (как делает GUI)
    if args.mobsf_url and args.stage3:
        try:
            validated_url = normalize_base_url(args.mobsf_url)
            if "mobsf" not in settings:
                settings["mobsf"] = {}
            settings["mobsf"]["url"] = validated_url
            save_settings(settings)
        except ValueError as exc:
            _err(f"Неверный MobSF URL: {exc}")
            return 1

    _section("TAPKA — Анализ APK")
    _info(f"APK:       {apk_path}")
    _info(f"Workspace: {workspace}")
    stages_requested = [
        s for s, flag in [("stage1", args.stage1), ("stage2", args.stage2), ("stage3", args.stage3)] if flag
    ]
    _info(f"Стадии:    {', '.join(stages_requested)}")

    # Инициализация Storage
    try:
        storage = Storage(workspace=workspace)
    except Exception as exc:
        _err(f"Не удалось инициализировать рабочую область: {exc}")
        return 1

    # Создаём проект
    _info("Создание проекта…")
    project = None
    for _attempt in range(3):
        try:
            project = storage.create_project(str(apk_path))
            _ok(f"Проект создан: {project.project_id}")
            break
        except FileExistsError:
            # project_id включает секунду — при редкой коллизии ждём секунду
            time.sleep(1)
        except Exception as exc:
            _err(f"Не удалось создать проект: {exc}")
            traceback.print_exc(file=sys.stderr)
            return 1
    if project is None:
        _err("Не удалось создать проект: конфликт имён после 3 попыток.")
        return 1

    project_id = project.project_id
    overall_ok = True

    # ── Stage 1 ───────────────────────────────────────────────────────────────
    if args.stage1:
        ok = run_stage1(storage, project_id)
        overall_ok = overall_ok and ok

    # ── Stage 2 ───────────────────────────────────────────────────────────────
    if args.stage2:
        cfg2 = Stage2Config(
            avd_name=args.avd,
            runtime_duration_sec=args.runtime,
            enable_https_interception=args.mitm_intercept,
            mitm_port=args.mitm_port,
        )
        ok = run_stage2(storage, project_id, cfg2)
        overall_ok = overall_ok and ok

    # ── Stage 3 ───────────────────────────────────────────────────────────────
    if args.stage3:
        cfg3 = Stage3BatchConfig(
            mobsf_config=Stage3Config(
                enable_dynamic_android=args.mobsf_dynamic,
                enable_dynamic_v2=args.mobsf_dynamic_v2,
                frida_steps=args.mobsf_frida,
                tls_tests=args.mobsf_tls_tests,
            ),
            quark_config=Stage3QuarkConfig(),
            apkid_config=Stage3ApkidConfig(),
            apkleaks_config=Stage3ApkleaksConfig(),
            skip_mobsf=args.no_mobsf,
            skip_quark=args.no_quark,
            skip_apkid=args.no_apkid,
            skip_apkleaks=args.no_apkleaks,
            tool_timeout_sec=None if args.no_timeout else 300,
        )
        ok = run_stage3(storage, project_id, cfg3)
        overall_ok = overall_ok and ok

    # ── Итоги ─────────────────────────────────────────────────────────────────
    _section("ИТОГИ")
    version_dir = storage.get_active_version_dir(project_id)
    _info(f"Проект:    {project_id}")
    _info(f"Каталог:   {version_dir / 'runs'}")

    # Security Score
    try:
        from analysis.reporting import ReportManager, ReportType
        from analysis.scoring import compute_score

        rm = ReportManager(storage)
        findings_by_stage = rm.load_all_findings(project_id)
        if findings_by_stage:
            sec_score = compute_score(findings_by_stage)
            _info(f"Security Score: {sec_score.total:.1f}/100  [{sec_score.risk_label.upper()}]")
            for stage_key, ss in sec_score.stages.items():
                _info(
                    f"  {stage_key}: normalized={ss.normalized:.1f}  "
                    f"high={ss.high_count}  medium={ss.medium_count}"
                )
    except Exception:  # pylint: disable=broad-exception-caught
        pass  # Score не критичен для exit code

    # Combined report output
    if args.output:
        try:
            from analysis.reporting import ReportManager, ReportType

            rm = ReportManager(storage)
            rt = ReportType.EXTENDED if args.report_type == "extended" else ReportType.STANDARD
            combined = rm.generate_combined_report(project_id, rt)
            import json as _json
            output_path = Path(args.output)
            output_path.write_text(combined.model_dump_json(indent=2, by_alias=True), encoding="utf-8")
            _ok(f"Отчёт сохранён: {output_path}")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            _err(f"Не удалось сохранить отчёт: {exc}")
            traceback.print_exc(file=sys.stderr)

    if overall_ok:
        _ok("Анализ завершён успешно.")
    else:
        _err("Анализ завершён с ошибками. Проверьте вывод выше.")

    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
