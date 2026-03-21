"""checksec runner — анализирует .so библиотеки APK на эксплуатируемость."""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal


RelroLevel = Literal["no", "partial", "full"]
ExploitabilityLevel = Literal["low", "medium", "high"]


@dataclass
class SoFileReport:
    name: str
    path: str
    nx: bool = False
    canary: bool = False
    pie: bool = False
    relro: RelroLevel = "no"
    fortify: bool = False
    exploitability: ExploitabilityLevel = "high"
    score: int = 0


def _exploitability_score(r: SoFileReport) -> int:
    """Чем выше score, тем выше эксплуатируемость (0–100)."""
    score = 0
    if not r.nx:
        score += 35
    if not r.canary:
        score += 25
    if not r.pie:
        score += 20
    if r.relro == "no":
        score += 15
    elif r.relro == "partial":
        score += 7
    if not r.fortify:
        score += 5
    return score


def _score_to_level(score: int) -> ExploitabilityLevel:
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _detect_checksec_backend() -> str:
    """Определяет доступный backend: checksec-py | bash | pwntools | none."""
    try:
        import checksec  # type: ignore[import-untyped]  # noqa: F401
        return "checksec-py"
    except ImportError:
        pass
    if shutil.which("checksec"):
        return "bash"
    try:
        import pwn  # type: ignore[import-untyped]  # noqa: F401
        return "pwntools"
    except ImportError:
        pass
    return "none"


def _parse_checksec_py(so_path: Path) -> dict:
    """Запускает checksec-py и возвращает сырой dict с флагами."""
    try:
        import checksec  # type: ignore[import-untyped]
        from checksec.elf import ELFSecurity, ELFChecksecData  # type: ignore[import-untyped]

        sec: ELFChecksecData = ELFSecurity(str(so_path)).checksec_data
        relro_val = str(getattr(sec, "relro", "no")).lower()
        if "full" in relro_val:
            relro: RelroLevel = "full"
        elif "partial" in relro_val:
            relro = "partial"
        else:
            relro = "no"
        return {
            "nx": bool(getattr(sec, "nx", False)),
            "canary": bool(getattr(sec, "canary", False)),
            "pie": bool(getattr(sec, "pie", False)),
            "relro": relro,
            "fortify": bool(getattr(sec, "fortify", False)),
        }
    except Exception:  # pylint: disable=broad-exception-caught
        return {}


def _parse_checksec_bash(so_path: Path) -> dict:
    """Запускает системный `checksec --output=json --file=...`."""
    try:
        result = subprocess.run(
            ["checksec", "--output=json", f"--file={so_path}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        raw = json.loads(result.stdout)
        # checksec wraps in {"filename": {...}}
        if isinstance(raw, dict):
            inner = next(iter(raw.values()), raw)
            if isinstance(inner, dict):
                raw = inner
        relro_str = str(raw.get("relro", "no")).lower()
        if "full" in relro_str:
            relro: RelroLevel = "full"
        elif "partial" in relro_str:
            relro = "partial"
        else:
            relro = "no"
        return {
            "nx": str(raw.get("nx", "no")).lower() not in ("no", "false", "0"),
            "canary": str(raw.get("canary", "no")).lower() not in ("no", "false", "0"),
            "pie": str(raw.get("pie", "no")).lower() not in ("no", "false", "0"),
            "relro": relro,
            "fortify": str(raw.get("fortify", "no")).lower() not in ("no", "false", "0"),
        }
    except Exception:  # pylint: disable=broad-exception-caught
        return {}


def _parse_pwntools(so_path: Path) -> dict:
    """Использует pwntools ELF для проверки флагов безопасности."""
    try:
        from pwn import ELF, context  # type: ignore[import-untyped]
        context.log_level = "error"
        elf = ELF(str(so_path), checksec=False)
        relro: RelroLevel
        if elf.relro == "Full":
            relro = "full"
        elif elf.relro == "Partial":
            relro = "partial"
        else:
            relro = "no"
        return {
            "nx": bool(elf.nx),
            "canary": bool(elf.canary),
            "pie": bool(elf.pie),
            "relro": relro,
            "fortify": bool(getattr(elf, "fortify", False)),
        }
    except Exception:  # pylint: disable=broad-exception-caught
        return {}


def _analyze_single(so_path: Path, backend: str) -> dict:
    if backend == "checksec-py":
        return _parse_checksec_py(so_path)
    if backend == "bash":
        return _parse_checksec_bash(so_path)
    if backend == "pwntools":
        return _parse_pwntools(so_path)
    return {}


def analyze_so_files(
    so_dir: Path,
    output_dir: Path,
    on_progress: Callable[[str], None] | None = None,
) -> list[SoFileReport]:
    """Анализирует все .so файлы в *so_dir* и возвращает список SoFileReport."""
    log = on_progress or (lambda m: None)

    backend = _detect_checksec_backend()
    if backend == "none":
        log("[checksec] Ни один backend не найден (checksec-py/checksec/pwntools) — пропускаем")
        return []

    log(f"[checksec] Backend: {backend}")
    so_files = list(so_dir.rglob("*.so")) if so_dir.exists() else []
    if not so_files:
        log("[checksec] .so файлов не найдено")
        return []

    log(f"[checksec] Анализ {len(so_files)} .so файлов")
    output_dir.mkdir(parents=True, exist_ok=True)

    reports: list[SoFileReport] = []
    for so_path in sorted(so_files):
        flags = _analyze_single(so_path, backend)
        if not flags:
            continue
        relro_val: RelroLevel = flags.get("relro", "no")  # type: ignore[assignment]
        r = SoFileReport(
            name=so_path.name,
            path=str(so_path),
            nx=bool(flags.get("nx", False)),
            canary=bool(flags.get("canary", False)),
            pie=bool(flags.get("pie", False)),
            relro=relro_val,
            fortify=bool(flags.get("fortify", False)),
        )
        r.score = _exploitability_score(r)
        r.exploitability = _score_to_level(r.score)
        reports.append(r)

    # Сохраняем JSON-артефакт
    try:
        output_json = output_dir / "checksec_results.json"
        payload = [
            {
                "name": r.name,
                "path": r.path,
                "nx": r.nx,
                "canary": r.canary,
                "pie": r.pie,
                "relro": r.relro,
                "fortify": r.fortify,
                "exploitability": r.exploitability,
                "score": r.score,
            }
            for r in reports
        ]
        output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError:
        pass

    log(f"[checksec] Готово: {len(reports)} файлов проанализировано")
    return reports
