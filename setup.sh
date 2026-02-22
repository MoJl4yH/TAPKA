#!/usr/bin/env bash
# setup.sh - TAPKA environment setup
# After completion: source .venv/bin/activate && python main.py

set -euo pipefail

# --- Colors and helpers -------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}[OK]${RESET}  $*"; }
fail() { echo -e "${RED}[ERR]${RESET} $*" >&2; }
info() { echo -e "${BLUE}[--]${RESET}  $*"; }
warn() { echo -e "${YELLOW}[!!]${RESET}  $*"; }
step() { echo -e "\n${BOLD}==> $*${RESET}"; }

# --- Variables ----------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
TAPKA_DIR="$SCRIPT_DIR/.tapka"
QUARK_RULES_DIR="$TAPKA_DIR/quark-rules"
QUARK_RULES_REPO="https://github.com/quark-engine/quark-rules"
MOBSF_IMAGE="opensecurity/mobile-security-framework-mobsf:latest"
PYTHON_MIN="3.11"

# Flags from CLI arguments
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
            echo "  --skip-apt    Skip system package installation via apt"
            echo "  --skip-mobsf  Skip MobSF Docker image download"
            echo "  --force-venv  Recreate .venv from scratch"
            exit 0
            ;;
    esac
done

# --- 0. OS check --------------------------------------------------------------
step "System check"

if [[ ! -f /etc/debian_version ]]; then
    warn "This script targets Debian/Ubuntu/Kali. Continuing, but apt steps may fail."
fi

# Python check
PYTHON_BIN=""
for py in python3.13 python3.12 python3.11 python3; do
    if command -v "$py" &>/dev/null; then
        ver=$("$py" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        # version comparison
        if python3 -c "import sys; sys.exit(0 if (int('$ver'.split('.')[0]), int('$ver'.split('.')[1])) >= ($(echo $PYTHON_MIN | tr '.' ',')) else 1)" 2>/dev/null; then
            PYTHON_BIN="$py"
            ok "Python $ver — $py"
            break
        fi
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    fail "Python >= $PYTHON_MIN not found. Install it with: sudo apt install python3"
    exit 1
fi

# --- 1. System dependencies via apt ------------------------------------------
step "System packages"

APT_PACKAGES=(
    # Java (required for apktool, jadx, keytool)
    default-jdk-headless
    # Android SDK tools
    android-sdk-build-tools   # aapt2, apksigner
    apktool
    jadx
    # Other Stage 1 tools
    ripgrep
    yara
    # Standard tools (usually preinstalled)
    binutils                  # strings
    file
    unzip
    # Docker for MobSF
    docker.io
    # Git (for quark-rules)
    git
)

if [[ "$SKIP_APT" -eq 1 ]]; then
    warn "Skipping apt package installation (--skip-apt)."
else
    if ! command -v apt-get &>/dev/null; then
        warn "apt-get not found; skipping system package installation."
    else
        info "Updating package index..."
        sudo apt-get update -qq

        info "Installing packages: ${APT_PACKAGES[*]}"
        sudo apt-get install -y --no-install-recommends "${APT_PACKAGES[@]}" \
            2>&1 | grep -E "^(Selecting|Unpacking|Setting up|Err:|E:)" || true
        ok "System packages installed."
    fi
fi

# --- 2. Verify Stage 1 tools --------------------------------------------------
step "Check Stage 1 tools"

MISSING_TOOLS=()
check_tool() {
    local name="$1"
    if command -v "$name" &>/dev/null; then
        ok "$name → $(command -v "$name")"
    else
        fail "$name not found"
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
    fail "Missing tools: ${MISSING_TOOLS[*]}"
    fail "Install them manually or rerun without --skip-apt"
    exit 1
fi

# ─── 3. Python venv ────────────────────────────────────────────────────────────
step "Python venv"

if [[ "$FORCE_VENV" -eq 1 && -d "$VENV_DIR" ]]; then
    info "Removing existing venv (--force-venv)..."
    rm -rf "$VENV_DIR"
fi

if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating venv at $VENV_DIR..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    ok "venv created."
else
    ok "venv already exists: $VENV_DIR"
fi

VENV_PIP="$VENV_DIR/bin/pip"
VENV_PYTHON="$VENV_DIR/bin/python"

# Upgrade pip
info "Upgrading pip..."
"$VENV_PIP" install --quiet --upgrade pip

# --- 4. Python dependencies ---------------------------------------------------
step "Python dependencies"

REQUIREMENTS="$SCRIPT_DIR/requirements.txt"
if [[ ! -f "$REQUIREMENTS" ]]; then
    fail "requirements.txt not found: $REQUIREMENTS"
    exit 1
fi

info "Installing from requirements.txt..."
"$VENV_PIP" install --quiet -r "$REQUIREMENTS"
ok "Python dependencies installed."

# Verify pip-installed CLI tools are available in venv
VENV_BIN="$VENV_DIR/bin"
for cli in quark apkid apkleaks; do
    if [[ -f "$VENV_BIN/$cli" ]]; then
        ok "$cli → $VENV_BIN/$cli"
    else
        warn "$cli not found in $VENV_BIN; installation may be incomplete."
    fi
done

# ─── 5. Quark rules ────────────────────────────────────────────────────────────
step "Quark rules"

mkdir -p "$TAPKA_DIR"

if [[ -d "$QUARK_RULES_DIR/.git" ]]; then
    info "quark-rules already cloned; updating..."
    git -C "$QUARK_RULES_DIR" pull --quiet --ff-only origin master 2>/dev/null \
        || git -C "$QUARK_RULES_DIR" pull --quiet --ff-only origin main 2>/dev/null \
        || warn "Could not update quark-rules (network issue or conflict). Using current copy."
    ok "quark-rules updated: $QUARK_RULES_DIR"
elif [[ -d "$QUARK_RULES_DIR" && ! -d "$QUARK_RULES_DIR/.git" ]]; then
    warn "$QUARK_RULES_DIR exists but is not a git repository. Skipping."
else
    info "Cloning quark-rules..."
    git clone --quiet --depth=1 "$QUARK_RULES_REPO" "$QUARK_RULES_DIR" \
        && ok "quark-rules cloned: $QUARK_RULES_DIR" \
        || { fail "Failed to clone quark-rules. Check network connectivity."; MISSING_TOOLS+=("quark-rules"); }
fi

# Verify rules/ structure
RULES_SUBDIR="$QUARK_RULES_DIR/rules"
if [[ ! -d "$RULES_SUBDIR" ]]; then
    RULES_SUBDIR="$QUARK_RULES_DIR"
fi
RULE_COUNT=$(find "$RULES_SUBDIR" -name "*.json" -maxdepth 1 2>/dev/null | wc -l)
if [[ "$RULE_COUNT" -gt 0 ]]; then
    ok "Found $RULE_COUNT Quark rules in $RULES_SUBDIR"
else
    warn "Quark JSON rules not found in $RULES_SUBDIR"
fi

# --- 6. YARA rules (bundle check) ---------------------------------------------
step "YARA rules"

YARA_BUNDLED="$SCRIPT_DIR/analysis/yara/android_spy_triage.yar"
if [[ -f "$YARA_BUNDLED" ]]; then
    ok "YARA rules: $YARA_BUNDLED"
else
    fail "YARA rules file not found: $YARA_BUNDLED"
    fail "This file is part of the repository. Ensure the clone is complete."
    MISSING_TOOLS+=("yara-rules")
fi

# --- 7. Docker group (for MobSF) ---------------------------------------------
step "Docker (MobSF)"

if ! command -v docker &>/dev/null; then
    warn "docker not found; MobSF (Stage3) will be unavailable."
elif ! docker info &>/dev/null 2>&1; then
    warn "Docker daemon unavailable or access denied."
    if ! groups | grep -qw docker; then
        warn "Current user is not in the docker group."
        echo -e "    Run:\n      ${BOLD}sudo usermod -aG docker \$USER${RESET}"
        echo -e "    Then re-login or run: ${BOLD}newgrp docker${RESET}"
    fi
else
    ok "Docker is available."

    if [[ "$SKIP_MOBSF" -eq 1 ]]; then
        warn "Skipping MobSF image pull (--skip-mobsf)."
    else
        if docker image inspect "$MOBSF_IMAGE" &>/dev/null 2>&1; then
            ok "MobSF image already present: $MOBSF_IMAGE"
        else
            info "Pulling MobSF Docker image (~2.6 GB, may take some time)..."
            if docker pull "$MOBSF_IMAGE"; then
                ok "MobSF image pulled: $MOBSF_IMAGE"
            else
                warn "Failed to pull MobSF image. Run manually: docker pull $MOBSF_IMAGE"
            fi
        fi
    fi
fi

# --- 8. Final import check ----------------------------------------------------
step "Final Python environment check"

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
    ok "PySide6, pydantic, requests import check: OK"
else
    fail "Import check failed: $IMPORT_CHECK"
    MISSING_TOOLS+=("python-imports")
fi

# --- 9. Summary ---------------------------------------------------------------
echo ""
echo -e "${BOLD}════════════════════════════════════════${RESET}"

if [[ ${#MISSING_TOOLS[@]} -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}Setup completed successfully.${RESET}"
    echo ""
    echo -e "Run the application:"
    echo -e "  ${BOLD}source $VENV_DIR/bin/activate${RESET}"
    echo -e "  ${BOLD}python main.py${RESET}"
    echo ""
    echo -e "Or run in one command from the project directory:"
    echo -e "  ${BOLD}$VENV_DIR/bin/python $SCRIPT_DIR/main.py${RESET}"
else
    echo -e "${YELLOW}${BOLD}Setup completed with warnings.${RESET}"
    echo -e "Unresolved items: ${MISSING_TOOLS[*]}"
    echo ""
    echo -e "The application may work partially."
fi

echo -e "${BOLD}════════════════════════════════════════${RESET}"
