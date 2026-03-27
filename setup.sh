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
TAPKA_DIR="$HOME/.tapka"
QUARK_RULES_DIR="$TAPKA_DIR/quark-rules"
QUARK_RULES_REPO="https://github.com/quark-engine/quark-rules"
SEMGREP_RULES_DIR="$TAPKA_DIR/semgrep-rules/mindedsecurity"
SEMGREP_RULES_REPO="https://github.com/mindedsecurity/semgrep-rules-android-security.git"
SEMGREP_REGISTRY_DIR="$TAPKA_DIR/semgrep-rules/registry"
SEMGREP_REGISTRY_BASE_URL="https://semgrep.dev/c"
MOBSF_UPSTREAM_IMAGE="opensecurity/mobile-security-framework-mobsf:latest"
MOBSF_IMAGE="tapka/mobsf:latest"
PYTHON_MIN="3.11"

# Flags from CLI arguments
SKIP_APT=0
SKIP_MOBSF=0
FORCE_VENV=0
WITH_STAGE2=0
UPDATE_MODE=0

for arg in "$@"; do
    case "$arg" in
        --skip-apt)    SKIP_APT=1 ;;
        --skip-mobsf)  SKIP_MOBSF=1 ;;
        --force-venv)  FORCE_VENV=1 ;;
        --with-stage2) WITH_STAGE2=1 ;;
        --update)      UPDATE_MODE=1 ;;
        --help|-h)
            echo "Usage: $0 [--skip-apt] [--skip-mobsf] [--force-venv] [--with-stage2] [--update]"
            echo "  --skip-apt    Skip system package installation via apt"
            echo "  --skip-mobsf  Skip MobSF Docker image download"
            echo "  --force-venv  Recreate .venv from scratch"
            echo "  --with-stage2 Install Android SDK, create AVD, and install Zeek for Stage 2"
            echo "  --update      Upgrade all Python dependencies to latest versions"
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
    # P1/P2 tools
    checksec                  # .so security analysis (NX/PIE/RELRO/canary)
    openssl                   # subject_hash_old for mitmproxy CA cert naming
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
check_tool openssl

# Soft checks for optional tools (warn, not fatal)
if command -v checksec &>/dev/null; then
    ok "checksec → $(command -v checksec)"
else
    warn "checksec not found (optional). .so security analysis will be limited."
fi

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

if [[ "$UPDATE_MODE" -eq 1 ]]; then
    info "Update mode: upgrading all packages..."
    "$VENV_PIP" install --quiet --upgrade -r "$REQUIREMENTS"
    ok "Python dependencies upgraded."
else
    info "Installing from requirements.txt..."
    "$VENV_PIP" install --quiet -r "$REQUIREMENTS"
    ok "Python dependencies installed."
fi

# setuptools<72 provides pkg_resources needed by opentelemetry-instrumentation
# (a transitive semgrep dependency). setuptools>=72 removed pkg_resources.
info "Pinning setuptools<72 for semgrep compatibility..."
"$VENV_PIP" install --quiet "setuptools<72"
ok "setuptools pinned."

# Verify pip-installed CLI tools are available in venv
VENV_BIN="$VENV_DIR/bin"
for cli in quark apkid apkleaks; do
    if [[ -f "$VENV_BIN/$cli" ]]; then
        ok "$cli → $VENV_BIN/$cli"
    else
        warn "$cli not found in $VENV_BIN; installation may be incomplete."
    fi
done

# Soft checks for pip-installed optional tools
for cli in semgrep mitmdump; do
    if [[ -f "$VENV_BIN/$cli" ]]; then
        ok "$cli → $VENV_BIN/$cli"
    else
        warn "$cli not found in $VENV_BIN (optional, but recommended)"
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

# --- 6b. checksec fallback ---------------------------------------------------
if ! command -v checksec &>/dev/null; then
    info "checksec not found in apt — trying GitHub fallback..."
    if wget -q -O /tmp/checksec \
        "https://raw.githubusercontent.com/slimm609/checksec.sh/main/checksec"; then
        chmod +x /tmp/checksec
        if sudo install /tmp/checksec /usr/local/bin/checksec 2>/dev/null; then
            ok "checksec installed to /usr/local/bin/checksec"
        else
            warn "Could not install checksec system-wide. .so analysis will be limited."
        fi
        rm -f /tmp/checksec
    else
        warn "Could not download checksec. .so security analysis will be skipped."
    fi
fi

# --- 6c. semgrep -----------------------------------------------------------
step "semgrep"

if [[ -f "$VENV_BIN/semgrep" ]]; then
    SEMGREP_VER=$("$VENV_BIN/semgrep" --version 2>/dev/null | head -1 || echo "unknown")
    ok "semgrep installed: $SEMGREP_VER"
else
    warn "semgrep not found in venv (pip install semgrep>=1.50.0)"
fi

# MindedSecurity MSTG rules
mkdir -p "$TAPKA_DIR/semgrep-rules"
if [[ -d "$SEMGREP_RULES_DIR/.git" ]]; then
    info "semgrep-rules/mindedsecurity already cloned; updating..."
    git -C "$SEMGREP_RULES_DIR" pull --quiet --ff-only origin main 2>/dev/null \
        || git -C "$SEMGREP_RULES_DIR" pull --quiet --ff-only origin master 2>/dev/null \
        || warn "Could not update semgrep-rules/mindedsecurity (network issue). Using current copy."
    ok "semgrep-rules/mindedsecurity updated: $SEMGREP_RULES_DIR"
elif [[ -d "$SEMGREP_RULES_DIR" && ! -d "$SEMGREP_RULES_DIR/.git" ]]; then
    warn "$SEMGREP_RULES_DIR exists but is not a git repository. Skipping."
else
    info "Cloning semgrep-rules/mindedsecurity..."
    git clone --quiet --depth=1 "$SEMGREP_RULES_REPO" "$SEMGREP_RULES_DIR" \
        && ok "semgrep-rules/mindedsecurity cloned: $SEMGREP_RULES_DIR" \
        || { fail "Failed to clone semgrep-rules/mindedsecurity. Check network connectivity."; MISSING_TOOLS+=("semgrep-rules"); }
fi

SEMGREP_RULE_COUNT=$(find "$SEMGREP_RULES_DIR/rules" -name "*.yaml" 2>/dev/null | wc -l)
if [[ "$SEMGREP_RULE_COUNT" -gt 0 ]]; then
    ok "Found $SEMGREP_RULE_COUNT MindedSecurity semgrep rules in $SEMGREP_RULES_DIR/rules"
else
    warn "MindedSecurity semgrep rules not found in $SEMGREP_RULES_DIR/rules"
fi

# Semgrep registry rules (offline copy)
mkdir -p "$SEMGREP_REGISTRY_DIR"
declare -A REGISTRY_RULESETS=(
    ["java-android-security"]="r/java.android.security"
    ["java-lang-security-audit"]="r/java.lang.security.audit"
    ["generic-secrets-gitleaks"]="r/generic.secrets.gitleaks"
)
REGISTRY_UPDATED=0
REGISTRY_FAILED=0
for name in "${!REGISTRY_RULESETS[@]}"; do
    ruleset="${REGISTRY_RULESETS[$name]}"
    dest="$SEMGREP_REGISTRY_DIR/${name}.yaml"
    if curl -sSf --max-time 30 "$SEMGREP_REGISTRY_BASE_URL/$ruleset" -o "$dest.tmp" 2>/dev/null; then
        mv "$dest.tmp" "$dest"
        REGISTRY_UPDATED=$((REGISTRY_UPDATED + 1))
    else
        rm -f "$dest.tmp"
        if [[ -f "$dest" ]]; then
            warn "Could not update $name (network issue). Using existing copy."
        else
            warn "Could not download $name — registry rules will be unavailable offline."
            REGISTRY_FAILED=$((REGISTRY_FAILED + 1))
        fi
    fi
done
if [[ "$REGISTRY_UPDATED" -gt 0 ]]; then
    ok "Semgrep registry rules downloaded/updated: $SEMGREP_REGISTRY_DIR ($REGISTRY_UPDATED rulesets)"
fi
if [[ "$REGISTRY_FAILED" -gt 0 ]]; then
    warn "$REGISTRY_FAILED registry ruleset(s) unavailable — run setup.sh again with network access"
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
        if docker image inspect "$MOBSF_UPSTREAM_IMAGE" &>/dev/null 2>&1; then
            ok "MobSF upstream image already present: $MOBSF_UPSTREAM_IMAGE"
        else
            info "Pulling MobSF Docker image (~2.6 GB, may take some time)..."
            if docker pull "$MOBSF_UPSTREAM_IMAGE"; then
                ok "MobSF image pulled: $MOBSF_UPSTREAM_IMAGE"
            else
                warn "Failed to pull MobSF image. Run manually: docker pull $MOBSF_UPSTREAM_IMAGE"
            fi
        fi

        # Build TAPKA-patched image (bakes in Android API 30 /system compatibility fixes).
        # Uses a one-line Dockerfile: FROM upstream + COPY patched environment.py.
        _PATCH="$SCRIPT_DIR/analysis/mobsf/patches/environment.py"
        _PATCH_DST="/home/mobsf/Mobile-Security-Framework-MobSF/mobsf/DynamicAnalyzer/views/android/environment.py"
        if docker image inspect "$MOBSF_UPSTREAM_IMAGE" &>/dev/null 2>&1 && [[ -f "$_PATCH" ]]; then
            if [[ "$UPDATE_MODE" -eq 1 ]] || ! docker image inspect "$MOBSF_IMAGE" &>/dev/null 2>&1; then
                info "Building $MOBSF_IMAGE (API 30 /system patches)..."
                _ctx=$(mktemp -d)
                cp "$_PATCH" "$_ctx/environment.py"
                # Patch frida_core.py: replace sys.stdin.read() with time.sleep(45).
                # In Docker, sys.stdin=/dev/null → read() returns immediately → session unloads
                # before hooks can capture any API calls.
                _FRIDA_CORE_PATCH="${SCRIPT_DIR}/analysis/mobsf/patches/frida_core.py"
                _FRIDA_CORE_DST="/home/mobsf/Mobile-Security-Framework-MobSF/mobsf/DynamicAnalyzer/views/android/frida_core.py"
                if [[ -f "${_FRIDA_CORE_PATCH}" ]]; then
                    cp "${_FRIDA_CORE_PATCH}" "$_ctx/frida_core.py"
                    _FRIDA_CORE_CMD="COPY frida_core.py ${_FRIDA_CORE_DST}"
                else
                    _FRIDA_CORE_CMD=""
                fi
                # Pre-cache frida-server 16.6.6 so frida_setup() doesn't need internet at runtime.
                _FRIDA_SERVER_CACHE="${SCRIPT_DIR}/analysis/mobsf/patches/frida-server-16.6.6-android-x86_64"
                if [[ -f "${_FRIDA_SERVER_CACHE}" ]]; then
                    cp "${_FRIDA_SERVER_CACHE}" "$_ctx/frida-server-16.6.6-android-x86_64"
                    _FRIDA_COPY_CMD="COPY frida-server-16.6.6-android-x86_64 /home/mobsf/.MobSF/downloads/frida-server-16.6.6-android-x86_64"
                else
                    _FRIDA_COPY_CMD=""
                fi
                # frida 17+ marks Android API 30 emulators as "jailed" (NotSupportedError on spawn).
                # Pinning to frida 16.x restores full access (no jailed restriction on userdebug builds).
                cat > "$_ctx/Dockerfile" <<EOF
FROM ${MOBSF_UPSTREAM_IMAGE}
COPY environment.py ${_PATCH_DST}
${_FRIDA_CORE_CMD}
${_FRIDA_COPY_CMD}
RUN pip install --quiet --no-cache-dir "frida==16.6.6" "frida-tools==12.5.1"
EOF
                docker build -q -t "$MOBSF_IMAGE" "$_ctx" \
                    && ok "$MOBSF_IMAGE built." \
                    || warn "$MOBSF_IMAGE build failed; runtime patching will be used as fallback."
                rm -rf "$_ctx"
            else
                ok "$MOBSF_IMAGE already present."
            fi
        fi
    fi
fi

# --- 8. Final import check ----------------------------------------------------
step "Final Python environment check"

# Check mitmproxy separately
if [[ -f "$VENV_BIN/mitmdump" ]]; then
    ok "mitmdump → $VENV_BIN/mitmdump"
else
    warn "mitmdump not found in venv. Stage 2 HTTPS interception unavailable."
    info "Install: pip install mitmproxy>=10.0.0"
fi

IMPORT_CHECK=$("$VENV_PYTHON" - <<'EOF' 2>&1
errors = []
warnings = []
for mod in ["PySide6", "pydantic", "requests"]:
    try:
        __import__(mod)
    except ImportError as e:
        errors.append(str(e))
for mod in ["semgrep", "mitmproxy"]:
    try:
        __import__(mod)
    except ImportError:
        warnings.append(f"{mod} (optional)")
if errors:
    print("FAIL: " + "; ".join(errors))
elif warnings:
    print("WARN: " + "; ".join(warnings))
else:
    print("OK")
EOF
)

if [[ "$IMPORT_CHECK" == "OK" ]]; then
    ok "Import check: OK"
elif [[ "$IMPORT_CHECK" == WARN:* ]]; then
    warn "Import check: $IMPORT_CHECK"
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

        info "Installing platform-tools, emulator, android-30 system image..."
        sdkmanager \
            "platform-tools" \
            "emulator" \
            "platforms;android-30" \
            "system-images;android-30;google_apis;x86_64" \
            && ok "Android SDK components installed." \
            || { fail "sdkmanager install failed."; MISSING_TOOLS+=("android-sdk-components"); }
    else
        warn "sdkmanager not found in PATH. Ensure cmdline-tools are correctly installed."
        MISSING_TOOLS+=("sdkmanager")
    fi

    # 10.4 Create AVD if it does not exist
    if command -v avdmanager &>/dev/null && command -v emulator &>/dev/null; then
        if emulator -list-avds 2>/dev/null | grep -q "tapka_api30"; then
            ok "AVD 'tapka_api30' already exists."
        else
            info "Creating AVD 'tapka_api30'..."
            echo "no" | avdmanager create avd \
                -n tapka_api30 \
                -k "system-images;android-30;google_apis;x86_64" \
                --device "pixel_5" \
                && ok "AVD 'tapka_api30' created." \
                || { fail "Failed to create AVD."; MISSING_TOOLS+=("avd-tapka_api30"); }
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
