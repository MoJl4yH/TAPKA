#!/usr/bin/env bash
# setup.sh — подготовка окружения TAPKA
# После выполнения: source .venv/bin/activate && python main.py

set -euo pipefail

# ─── Цвета и хелперы ───────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}[OK]${RESET}  $*"; }
fail() { echo -e "${RED}[ERR]${RESET} $*" >&2; }
info() { echo -e "${BLUE}[--]${RESET}  $*"; }
warn() { echo -e "${YELLOW}[!!]${RESET}  $*"; }
step() { echo -e "\n${BOLD}==> $*${RESET}"; }

# ─── Переменные ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
TAPKA_DIR="$SCRIPT_DIR/.tapka"
QUARK_RULES_DIR="$TAPKA_DIR/quark-rules"
QUARK_RULES_REPO="https://github.com/quark-engine/quark-rules"
MOBSF_IMAGE="opensecurity/mobile-security-framework-mobsf:latest"
PYTHON_MIN="3.11"

# Флаги из аргументов
SKIP_APT=0
SKIP_MOBSF=0
FORCE_VENV=0

for arg in "$@"; do
    case "$arg" in
        --skip-apt)   SKIP_APT=1 ;;
        --skip-mobsf) SKIP_MOBSF=1 ;;
        --force-venv) FORCE_VENV=1 ;;
        --help|-h)
            echo "Usage: $0 [--skip-apt] [--skip-mobsf] [--force-venv]"
            echo "  --skip-apt    Не устанавливать системные пакеты через apt"
            echo "  --skip-mobsf  Не скачивать Docker-образ MobSF"
            echo "  --force-venv  Пересоздать .venv с нуля"
            exit 0
            ;;
    esac
done

# ─── 0. Проверка ОС ────────────────────────────────────────────────────────────
step "Проверка системы"

if [[ ! -f /etc/debian_version ]]; then
    warn "Этот скрипт рассчитан на Debian/Ubuntu/Kali. Продолжаем, но apt-шаги могут не работать."
fi

# Проверка Python
PYTHON_BIN=""
for py in python3.13 python3.12 python3.11 python3; do
    if command -v "$py" &>/dev/null; then
        ver=$("$py" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        # сравнение версий
        if python3 -c "import sys; sys.exit(0 if (int('$ver'.split('.')[0]), int('$ver'.split('.')[1])) >= ($(echo $PYTHON_MIN | tr '.' ',')) else 1)" 2>/dev/null; then
            PYTHON_BIN="$py"
            ok "Python $ver — $py"
            break
        fi
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    fail "Python >= $PYTHON_MIN не найден. Установите: sudo apt install python3"
    exit 1
fi

# ─── 1. Системные зависимости через apt ───────────────────────────────────────
step "Системные пакеты"

APT_PACKAGES=(
    # Java (нужна для apktool, jadx, keytool)
    default-jdk-headless
    # Android SDK утилиты
    android-sdk-build-tools   # aapt2, apksigner
    apktool
    jadx
    # Остальные утилиты stage1
    ripgrep
    yara
    # Стандартные утилиты (обычно уже есть)
    binutils                  # strings
    file
    unzip
    # Docker для MobSF
    docker.io
    # Git (для quark-rules)
    git
)

if [[ "$SKIP_APT" -eq 1 ]]; then
    warn "Пропуск установки apt-пакетов (--skip-apt)."
else
    if ! command -v apt-get &>/dev/null; then
        warn "apt-get не найден — пропуск установки системных пакетов."
    else
        info "Обновление списка пакетов..."
        sudo apt-get update -qq

        info "Установка пакетов: ${APT_PACKAGES[*]}"
        sudo apt-get install -y --no-install-recommends "${APT_PACKAGES[@]}" \
            2>&1 | grep -E "^(Selecting|Unpacking|Setting up|Err:|E:)" || true
        ok "Системные пакеты установлены."
    fi
fi

# ─── 2. Проверка наличия всех инструментов stage1 ──────────────────────────────
step "Проверка инструментов Stage1"

MISSING_TOOLS=()
check_tool() {
    local name="$1"
    if command -v "$name" &>/dev/null; then
        ok "$name → $(command -v "$name")"
    else
        fail "$name — не найден"
        MISSING_TOOLS+=("$name")
    fi
}

check_tool java
check_tool keytool
check_tool apktool
check_tool jadx
check_tool aapt2
check_tool apksigner
check_tool yara
check_tool rg
check_tool strings
check_tool file
check_tool stat
check_tool sha256sum
check_tool unzip
check_tool grep
check_tool git
check_tool docker

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    fail "Не найдены инструменты: ${MISSING_TOOLS[*]}"
    fail "Установите их вручную или повторите без --skip-apt"
    exit 1
fi

# ─── 3. Python venv ────────────────────────────────────────────────────────────
step "Python venv"

if [[ "$FORCE_VENV" -eq 1 && -d "$VENV_DIR" ]]; then
    info "Удаление существующего venv (--force-venv)..."
    rm -rf "$VENV_DIR"
fi

if [[ ! -d "$VENV_DIR" ]]; then
    info "Создание venv в $VENV_DIR..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    ok "venv создан."
else
    ok "venv уже существует: $VENV_DIR"
fi

VENV_PIP="$VENV_DIR/bin/pip"
VENV_PYTHON="$VENV_DIR/bin/python"

# Обновить pip
info "Обновление pip..."
"$VENV_PIP" install --quiet --upgrade pip

# ─── 4. Python зависимости ─────────────────────────────────────────────────────
step "Python зависимости"

REQUIREMENTS="$SCRIPT_DIR/requirements.txt"
if [[ ! -f "$REQUIREMENTS" ]]; then
    fail "requirements.txt не найден: $REQUIREMENTS"
    exit 1
fi

info "Установка из requirements.txt..."
"$VENV_PIP" install --quiet -r "$REQUIREMENTS"
ok "Python зависимости установлены."

# Проверить что CLI утилиты от pip доступны в venv
VENV_BIN="$VENV_DIR/bin"
for cli in quark apkid apkleaks; do
    if [[ -f "$VENV_BIN/$cli" ]]; then
        ok "$cli → $VENV_BIN/$cli"
    else
        warn "$cli не найден в $VENV_BIN — возможно, установка не завершилась."
    fi
done

# ─── 5. Quark rules ────────────────────────────────────────────────────────────
step "Quark rules"

mkdir -p "$TAPKA_DIR"

if [[ -d "$QUARK_RULES_DIR/.git" ]]; then
    info "quark-rules уже склонированы — обновляем..."
    git -C "$QUARK_RULES_DIR" pull --quiet --ff-only origin master 2>/dev/null \
        || git -C "$QUARK_RULES_DIR" pull --quiet --ff-only origin main 2>/dev/null \
        || warn "Не удалось обновить quark-rules (нет сети или конфликт). Используем текущую версию."
    ok "quark-rules обновлены: $QUARK_RULES_DIR"
elif [[ -d "$QUARK_RULES_DIR" && ! -d "$QUARK_RULES_DIR/.git" ]]; then
    warn "$QUARK_RULES_DIR существует, но не является git-репо. Пропуск."
else
    info "Клонирование quark-rules..."
    git clone --quiet --depth=1 "$QUARK_RULES_REPO" "$QUARK_RULES_DIR" \
        && ok "quark-rules склонированы: $QUARK_RULES_DIR" \
        || { fail "Не удалось клонировать quark-rules. Проверьте сеть."; MISSING_TOOLS+=("quark-rules"); }
fi

# Проверить структуру rules/
RULES_SUBDIR="$QUARK_RULES_DIR/rules"
if [[ ! -d "$RULES_SUBDIR" ]]; then
    RULES_SUBDIR="$QUARK_RULES_DIR"
fi
RULE_COUNT=$(find "$RULES_SUBDIR" -name "*.json" -maxdepth 1 2>/dev/null | wc -l)
if [[ "$RULE_COUNT" -gt 0 ]]; then
    ok "Найдено $RULE_COUNT правил Quark в $RULES_SUBDIR"
else
    warn "JSON-правила Quark не найдены в $RULES_SUBDIR"
fi

# ─── 6. YARA rules (проверка бандла) ──────────────────────────────────────────
step "YARA rules"

YARA_BUNDLED="$SCRIPT_DIR/analysis/yara/android_spy_triage.yar"
if [[ -f "$YARA_BUNDLED" ]]; then
    ok "YARA rules: $YARA_BUNDLED"
else
    fail "Файл YARA rules не найден: $YARA_BUNDLED"
    fail "Это файл из репозитория — убедитесь что git clone выполнен полностью."
    MISSING_TOOLS+=("yara-rules")
fi

# ─── 7. Docker группа (для MobSF) ─────────────────────────────────────────────
step "Docker (MobSF)"

if ! command -v docker &>/dev/null; then
    warn "docker не найден — MobSF (Stage3) работать не будет."
elif ! docker info &>/dev/null 2>&1; then
    warn "Docker daemon недоступен или нет прав."
    if ! groups | grep -qw docker; then
        warn "Пользователь не в группе docker."
        echo -e "    Выполните:\n      ${BOLD}sudo usermod -aG docker \$USER${RESET}"
        echo -e "    Затем перелогиньтесь или выполните: ${BOLD}newgrp docker${RESET}"
    fi
else
    ok "Docker доступен."

    if [[ "$SKIP_MOBSF" -eq 1 ]]; then
        warn "Пропуск загрузки MobSF образа (--skip-mobsf)."
    else
        if docker image inspect "$MOBSF_IMAGE" &>/dev/null 2>&1; then
            ok "MobSF образ уже загружен: $MOBSF_IMAGE"
        else
            info "Загрузка MobSF Docker-образа (~2.6 ГБ, может занять время)..."
            if docker pull "$MOBSF_IMAGE"; then
                ok "MobSF образ загружен: $MOBSF_IMAGE"
            else
                warn "Не удалось загрузить MobSF. Запустите вручную: docker pull $MOBSF_IMAGE"
            fi
        fi
    fi
fi

# ─── 8. Финальная проверка импорта ────────────────────────────────────────────
step "Финальная проверка Python окружения"

IMPORT_CHECK=$("$VENV_PYTHON" - <<'EOF' 2>&1
errors = []
for mod in ["PySide6", "pydantic", "requests"]:
    try:
        __import__(mod)
    except ImportError as e:
        errors.append(str(e))
if errors:
    print("FAIL: " + "; ".join(errors))
else:
    print("OK")
EOF
)

if [[ "$IMPORT_CHECK" == "OK" ]]; then
    ok "Импорт PySide6, pydantic, requests — OK"
else
    fail "Проблема с импортом: $IMPORT_CHECK"
    MISSING_TOOLS+=("python-imports")
fi

# ─── 9. Итог ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════${RESET}"

if [[ ${#MISSING_TOOLS[@]} -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}Установка завершена успешно!${RESET}"
    echo ""
    echo -e "Запуск приложения:"
    echo -e "  ${BOLD}source $VENV_DIR/bin/activate${RESET}"
    echo -e "  ${BOLD}python main.py${RESET}"
    echo ""
    echo -e "Или одной командой из папки проекта:"
    echo -e "  ${BOLD}$VENV_DIR/bin/python $SCRIPT_DIR/main.py${RESET}"
else
    echo -e "${YELLOW}${BOLD}Установка завершена с предупреждениями.${RESET}"
    echo -e "Не решены: ${MISSING_TOOLS[*]}"
    echo ""
    echo -e "Приложение может работать частично."
fi

echo -e "${BOLD}════════════════════════════════════════${RESET}"
