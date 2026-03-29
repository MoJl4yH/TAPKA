#!/usr/bin/env bash
# batch_analyze.sh — последовательный анализ всех APK из директории
#
# Использование:
#   ./batch_analyze.sh /path/to/apk_dir [--stage1|--all|...]
#
# Примеры:
#   ./batch_analyze.sh ./apks --stage1
#   ./batch_analyze.sh ./apks --all --output-dir ./reports
#   ./batch_analyze.sh ./apks --stage1 --stage3 --no-mobsf

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI="$SCRIPT_DIR/tapka_cli.py"

# ── Аргументы ─────────────────────────────────────────────────────────────────
APK_DIR="${1:?Укажите директорию с APK: ./batch_analyze.sh /path/to/apks [flags]}"
shift

OUTPUT_DIR=""
TAPKA_ARGS=()
for arg in "$@"; do
    if [[ "$arg" == --output-dir=* ]]; then
        OUTPUT_DIR="${arg#--output-dir=}"
    elif [[ "$arg" == "--output-dir" ]]; then
        # handled by next iteration — skip; user should use --output-dir=PATH form
        :
    else
        TAPKA_ARGS+=("$arg")
    fi
done

# ── Проверки ──────────────────────────────────────────────────────────────────
if [[ ! -d "$APK_DIR" ]]; then
    echo "[batch] Директория не найдена: $APK_DIR" >&2
    exit 1
fi

if [[ ${#TAPKA_ARGS[@]} -eq 0 ]]; then
    echo "[batch] Не указаны флаги tapka. Добавь --stage1 или --all"
    echo "        Пример: ./batch_analyze.sh ./apks --stage1"
    exit 1
fi

if [[ -n "$OUTPUT_DIR" ]]; then
    mkdir -p "$OUTPUT_DIR"
fi

# ── Сбор APK ─────────────────────────────────────────────────────────────────
mapfile -t APK_FILES < <(find "$APK_DIR" -maxdepth 1 -name "*.apk" | sort)

TOTAL=${#APK_FILES[@]}
if [[ $TOTAL -eq 0 ]]; then
    echo "[batch] APK-файлы не найдены в: $APK_DIR"
    exit 0
fi

echo "═══════════════════════════════════════════════════════════════"
echo "  TAPKA Batch Analyze"
echo "  Директория: $APK_DIR"
echo "  Найдено APK: $TOTAL"
echo "  Флаги: ${TAPKA_ARGS[*]}"
[[ -n "$OUTPUT_DIR" ]] && echo "  Отчёты: $OUTPUT_DIR"
echo "═══════════════════════════════════════════════════════════════"

# ── Анализ ────────────────────────────────────────────────────────────────────
PASSED=0
FAILED=0
FAILED_LIST=()
BATCH_START=$(date +%s)

for i in "${!APK_FILES[@]}"; do
    apk="${APK_FILES[$i]}"
    name="$(basename "$apk")"
    num=$((i + 1))

    echo ""
    echo "───────────────────────────────────────────────────────────────"
    echo "  [$num/$TOTAL] $name"
    echo "───────────────────────────────────────────────────────────────"

    CMD=(python3 "$CLI" "$apk" "${TAPKA_ARGS[@]}")

    # Добавляем --output если указан --output-dir
    if [[ -n "$OUTPUT_DIR" ]]; then
        stem="${name%.apk}"
        out_file="$OUTPUT_DIR/${stem}.report.json"
        CMD+=(--output "$out_file")
    fi

    START=$(date +%s)
    if "${CMD[@]}"; then
        END=$(date +%s)
        echo "[batch] ✓ $name — OK ($(( END - START ))s)"
        PASSED=$((PASSED + 1))
    else
        END=$(date +%s)
        echo "[batch] ✗ $name — FAILED ($(( END - START ))s)" >&2
        FAILED=$((FAILED + 1))
        FAILED_LIST+=("$name")
    fi
done

# ── Итог ──────────────────────────────────────────────────────────────────────
BATCH_END=$(date +%s)
TOTAL_SEC=$(( BATCH_END - BATCH_START ))

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ИТОГИ"
echo "  Всего: $TOTAL   ✓ OK: $PASSED   ✗ Ошибок: $FAILED"
printf "  Время: %dm %ds\n" $(( TOTAL_SEC / 60 )) $(( TOTAL_SEC % 60 ))
if [[ ${#FAILED_LIST[@]} -gt 0 ]]; then
    echo "  Упали:"
    for f in "${FAILED_LIST[@]}"; do
        echo "    - $f"
    done
fi
echo "═══════════════════════════════════════════════════════════════"

[[ $FAILED -eq 0 ]] && exit 0 || exit 1
