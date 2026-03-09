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

WITH_STAGE2=0

for arg in "$@"; do
    case "$arg" in
        --skip-apt)    SKIP_APT=1 ;;
        --skip-mobsf)  SKIP_MOBSF=1 ;;
        --force-venv)  FORCE_VENV=1 ;;
        --with-stage2) WITH_STAGE2=1 ;;
        --help|-h)
            echo "Usage: $0 [--skip-apt] [--skip-mobsf] [--force-venv] [--with-stage2]"
            echo "  --skip-apt    Skip system package installation via apt"
            echo "  --skip-mobsf  Skip MobSF Docker image download"
            echo "  --force-venv  Recreate .venv from scratch"
            echo "  --with-stage2 Install Android SDK, create AVD, and install Zeek for Stage 2"
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

# --- 10. Stage 2: Android SDK + AVD + Zeek (optional) -------------------------
if [[ "$WITH_STAGE2" -eq 1 ]]; then
    step "Stage 2 setup (Android SDK, AVD, Zeek)"

    ANDROID_SDK_ROOT="$HOME/android-sdk"
    ANDROID_AVD_HOME="$HOME/.config/.android/avd"
    CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
    CMDLINE_TOOLS_ZIP="$ANDROID_SDK_ROOT/cmdline-tools.zip"
    CMDLINE_TOOLS_DEST="$ANDROID_SDK_ROOT/cmdline-tools/latest"

    export ANDROID_SDK_ROOT
    export ANDROID_AVD_HOME
    export PATH="$CMDLINE_TOOLS_DEST/bin:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$PATH"

    # 10.1 OS dependencies for emulator
    info "Installing emulator OS dependencies..."
    sudo apt-get install -y --no-install-recommends \
        openjdk-17-jdk libgl1 libpulse0 libnss3 libx11-6 libxcomposite1 \
        libxcursor1 libxdamage1 libxrandr2 libxtst6 \
        2>&1 | grep -E "^(Selecting|Unpacking|Setting up|Err:|E:)" || true
    ok "Emulator OS dependencies installed."

    # 10.2 Download cmdline-tools if not present
    mkdir -p "$ANDROID_SDK_ROOT"
    if [[ ! -f "$CMDLINE_TOOLS_DEST/bin/sdkmanager" ]]; then
        info "Downloading Android cmdline-tools..."
        wget -q -O "$CMDLINE_TOOLS_ZIP" "$CMDLINE_TOOLS_URL" \
            && ok "Downloaded cmdline-tools." \
            || { fail "Failed to download cmdline-tools. Check network connectivity."; MISSING_TOOLS+=("cmdline-tools"); }

        if [[ -f "$CMDLINE_TOOLS_ZIP" ]]; then
            TMP_UNZIP="$ANDROID_SDK_ROOT/_cmdline_unzip"
            mkdir -p "$TMP_UNZIP"
            unzip -q "$CMDLINE_TOOLS_ZIP" -d "$TMP_UNZIP"
            mkdir -p "$CMDLINE_TOOLS_DEST"
            if [[ -d "$TMP_UNZIP/cmdline-tools" ]]; then
                cp -r "$TMP_UNZIP/cmdline-tools/." "$CMDLINE_TOOLS_DEST/"
            else
                cp -r "$TMP_UNZIP/." "$CMDLINE_TOOLS_DEST/"
            fi
            rm -rf "$TMP_UNZIP" "$CMDLINE_TOOLS_ZIP"
            ok "cmdline-tools installed at $CMDLINE_TOOLS_DEST"
        fi
    else
        ok "cmdline-tools already installed: $CMDLINE_TOOLS_DEST"
    fi

    # 10.3 Accept licenses and install SDK components
    if command -v sdkmanager &>/dev/null; then
        info "Accepting Android SDK licenses..."
        yes | sdkmanager --licenses >/dev/null 2>&1 || true

        info "Installing platform-tools, emulator, android-35 system image..."
        sdkmanager \
            "platform-tools" \
            "emulator" \
            "platforms;android-35" \
            "system-images;android-35;google_apis;x86_64" \
            && ok "Android SDK components installed." \
            || { fail "sdkmanager install failed."; MISSING_TOOLS+=("android-sdk-components"); }
    else
        warn "sdkmanager not found in PATH. Ensure cmdline-tools are correctly installed."
        MISSING_TOOLS+=("sdkmanager")
    fi

    # 10.4 Create AVD if it does not exist
    if command -v avdmanager &>/dev/null && command -v emulator &>/dev/null; then
        if emulator -list-avds 2>/dev/null | grep -q "tapka_api35"; then
            ok "AVD 'tapka_api35' already exists."
        else
            info "Creating AVD 'tapka_api35'..."
            echo "no" | avdmanager create avd \
                -n tapka_api35 \
                -k "system-images;android-35;google_apis;x86_64" \
                --device "pixel_5" \
                && ok "AVD 'tapka_api35' created." \
                || { fail "Failed to create AVD."; MISSING_TOOLS+=("avd-tapka_api35"); }
        fi
    else
        warn "avdmanager or emulator not found; skipping AVD creation."
        MISSING_TOOLS+=("avdmanager")
    fi

    # 10.5 KVM group check
    if groups | grep -qw kvm; then
        ok "User is in the kvm group."
    else
        warn "User is NOT in the kvm group. Emulator will be slow without hardware virtualization."
        echo -e "    Run:\n      ${BOLD}sudo adduser \$USER kvm${RESET}"
        echo -e "    Then re-login for the change to take effect."
    fi

    # 10.6 Install tshark for pcap analysis (Zeek is optional but often broken on Kali)
    if command -v tshark &>/dev/null; then
        ok "tshark already installed: $(command -v tshark)"
    else
        info "Installing tshark (pcap analysis)..."
        if sudo apt-get install -y tshark 2>/dev/null; then
            ok "tshark installed."
        else
            warn "tshark could not be installed. pcap will be captured but not auto-analyzed."
        fi
    fi

    # Zeek is optional and often has broken deps on Kali — just check, don't force-install
    if command -v zeek &>/dev/null; then
        ok "Zeek also available: $(command -v zeek) (will be preferred over tshark)"
    else
        info "Zeek not installed (optional). tshark will be used for pcap analysis."
        info "To install Zeek manually: https://zeek.org/get-zeek/"
    fi

    ok "Stage 2 setup complete."
fi
