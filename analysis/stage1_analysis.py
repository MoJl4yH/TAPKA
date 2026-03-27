import hashlib
import ipaddress
import json
import re
import shutil
import time
import traceback
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, TextIO
import xml.etree.ElementTree as ET

from analysis.runner import run_command
from analysis.reporting import ReportManager
from analysis.stages import STAGE_STATIC
from analysis.severity import SeverityEngine
from analysis.storage import Storage
from models import Run, Finding, CommandResult


@dataclass(frozen=True)
class FindingSpec:
    category: str
    evidence: str
    file_path: str = ""
    line: int | None = None
    column: int | None = None
    confidence: str = "C1"
    evidence_type: str = "string"
    tags: set[str] = field(default_factory=set)
    sources: list[str] = field(default_factory=list)
    source: str | None = None


@dataclass(frozen=True)
class Stage1Paths:
    run_dir: Path
    logs_dir: Path
    artifacts_dir: Path
    apktool_dir: Path
    jadx_dir: Path
    certs_dir: Path


@dataclass
class ProgressTracker:
    runner: "Stage1StaticRunner"
    log: Callable[[str], None]
    total_steps: int
    overall_start: float
    current_message: str = "Подготовка этапа 1"
    completed_steps: int = 0
    step_durations: list[float] = field(default_factory=list)

    def estimate_eta(self) -> int | None:
        if not self.step_durations or self.total_steps <= self.completed_steps:
            return None
        avg = sum(self.step_durations) / len(self.step_durations)
        remaining = self.total_steps - self.completed_steps
        return max(0, int(avg * remaining))

    def emit(self) -> None:
        elapsed = time.monotonic() - self.overall_start
        self.runner._emit_progress(
            self.current_message,
            self.completed_steps,
            self.total_steps,
            elapsed,
            self.estimate_eta(),
        )

    def update_total_steps(self, new_total: int, message: str) -> None:
        self.total_steps = new_total
        self.current_message = message
        self.emit()

    def run_step(self, label: str, func):
        self.current_message = f"Выполняется: {label}"
        self.log(self.current_message)
        self.emit()
        step_start = time.monotonic()
        result = func()
        self.step_durations.append(time.monotonic() - step_start)
        self.completed_steps += 1
        self.emit()
        return result


@dataclass
class PipelineState:
    cert_names: list[str]
    so_count_estimate: int
    rg_step_count: int
    progress: ProgressTracker


class Stage1StaticRunner:
    REQUIRED_TOOLS = [
        "file",
        "stat",
        "sha256sum",
        "apksigner",
        "aapt2",
        "unzip",
        "grep",
        "keytool",
        "apktool",
        "jadx",
        "rg",
        "strings",
        "yara",
    ]
    CERT_LIST_PATTERN = r"META-INF/.*\.(RSA|DSA|EC)$"
    JADX_PARTIAL_PATTERN = re.compile(r"finished with errors", re.IGNORECASE)
    APKTOOL_FLEX_PATTERN = re.compile(r"flex scanner failed", re.IGNORECASE)
    RG_PATTERN_SPECS = [
        {
            "category": "secret_endpoints_hardcoded",
            "pattern": r'(https?|wss?|ftp|grpc|grpcs|mqtts?|rtsp)://(?!schemas\.android\.com)[^" <>{}]{8,}',
            "targets": ("apktool", "jadx"),
            "scope": "app_res",
            "confidence": "C1",
            "evidence_type": "string",
            "tags": {"network"},
            "source": "endpoint_url",
        },
        {
            "category": "secret_endpoints_hardcoded",
            "pattern": r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
            "targets": ("apktool", "jadx"),
            "scope": "app_res",
            "confidence": "C1",
            "evidence_type": "string",
            "tags": {"network"},
            "source": "endpoint_ipv4",
        },
        {
            "category": "secret_sensitive_kv",
            "pattern": r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|auth[_-]?token|access[_-]?token|private[_-]?key)\b\s*[:=>]\s*[\"'][A-Za-z0-9+/=_\-.]{8,}[\"']",
            "targets": ("apktool", "jadx"),
            "scope": "app_res",
            "confidence": "C1",
            "evidence_type": "string",
            "tags": set(),
            "source": "secret_kv",
        },
        {
            "category": "secret_jwt_embedded",
            "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "targets": ("apktool", "jadx"),
            "scope": "full",
            "confidence": "C1",
            "evidence_type": "string",
            "tags": set(),
            "source": "jwt",
        },
        {
            "category": "secret_private_key_pem",
            "pattern": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
            "targets": ("apktool", "jadx"),
            "scope": "full",
            "confidence": "C1",
            "evidence_type": "string",
            "tags": set(),
            "source": "private_key_pem",
        },
        {
            "category": "ndv_dynamic_code_loading_dex",
            "pattern": r"\b(DexClassLoader|InMemoryDexClassLoader|PathClassLoader|BaseDexClassLoader)\b|\.loadDex\(|\.defineClass\(",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"dynamic_code"},
            "source": "dex_class_loader",
        },
        {
            "category": "signal_payload_decode",
            "pattern": r"Base64\.decode\(",
            "targets": ("jadx",),
            "scope": "app",
            "confidence": "C1",
            "evidence_type": "code",
            "tags": set(),
            "source": "payload_decode_base64",
        },
        {
            "category": "signal_payload_decode",
            "pattern": r"Cipher\.doFinal\(",
            "targets": ("jadx",),
            "scope": "app",
            "confidence": "C1",
            "evidence_type": "code",
            "tags": set(),
            "source": "payload_decode_cipher",
        },
        {
            "category": "signal_download_manager",
            "pattern": r"DownloadManager\.enqueue\(|DownloadManager\.Request\(",
            "targets": ("jadx",),
            "scope": "app",
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"network"},
            "source": "download_manager",
        },
        {
            "category": "ndv_reflection_heavy",
            "pattern": r"Class\.forName\(|\.getDeclaredMethod\(|\.getDeclaredField\(|Method\.invoke\(",
            "targets": ("jadx",),
            "scope": "app",
            "confidence": "C1",
            "evidence_type": "code",
            "tags": set(),
            "source": "reflection",
        },
        {
            "category": "ndv_remote_command_shell",
            "pattern": r"Runtime\.getRuntime\(\)\.exec\(|new\s+ProcessBuilder\(",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"dynamic_code"},
            "source": "shell_exec",
        },
        {
            "category": "ndv_native_code_loader_suspicious",
            "pattern": r"System\.loadLibrary\(|System\.load\(",
            "targets": ("jadx",),
            "confidence": "C1",
            "evidence_type": "code",
            "tags": set(),
            "source": "native_loader",
        },
        {
            "category": "sec_insecure_webview_bridge",
            "pattern": r"addJavascriptInterface",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "webview_js_bridge",
        },
        {
            "category": "sec_insecure_webview_file_access",
            "pattern": r"setAllowFileAccess|setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "webview_file_access",
        },
        {
            "category": "sec_tls_trust_all",
            "pattern": r"checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|checkServerTrusted[^}]*return\s*;",
            "targets": ("jadx",),
            "confidence": "C3",
            "evidence_type": "code",
            "tags": {"mitm_enabler"},
            "source": "tls_trust_all_empty",
        },
        {
            "category": "sec_tls_trust_all",
            "pattern": r"ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|TrustAllCerts|TrustAllManager|InsecureTrustManager",
            "targets": ("jadx",),
            "confidence": "C3",
            "evidence_type": "code",
            "tags": {"mitm_enabler"},
            "source": "tls_trust_all_named",
        },
        {
            "category": "sec_hostname_verifier_bypass",
            "pattern": r"ALLOW_ALL_HOSTNAME_VERIFIER|verify\s*\([^)]*\)\s*\{[^}]*return\s+true|HostnameVerifier\s*\(\s*\)\s*->?\s*true",
            "targets": ("jadx",),
            "confidence": "C3",
            "evidence_type": "code",
            "tags": {"mitm_enabler"},
            "source": "hostname_verifier_bypass",
        },
        {
            "category": "sec_custom_ca_store_or_user_certs",
            "pattern": r"\.setCertificateEntry\(|TrustManagerFactory\.init\(|KeyStore\.getInstance\(\"BKS\"\)",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "custom_ca_store",
        },
        {
            "category": "sec_proxy_setting_modification",
            "pattern": r"settings\s+put\s+global\s+http_proxy",
            "targets": ("jadx", "apktool"),
            "confidence": "C1",
            "evidence_type": "string",
            "tags": set(),
            "source": "proxy_setting",
        },
        {
            "category": "vul_pendingintent_mutable",
            "pattern": r"FLAG_MUTABLE|PendingIntent\.FLAG_MUTABLE",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "pendingintent_mutable",
        },
        {
            "category": "ndv_clipboard_monitoring",
            # Exclude copy-to-clipboard UI patterns (setPrimaryClip / newPlainText) which are benign
            "pattern": r"getPrimaryClip|addPrimaryClipChangedListener",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "clipboard_monitor",
        },
        {
            "category": "ndv_notification_listener",
            "pattern": r"NotificationListenerService",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "notification_listener",
        },
        {
            "category": "ndv_overlay_abuse",
            "pattern": r"TYPE_APPLICATION_OVERLAY",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "overlay_type",
        },
        {
            "category": "ndv_screen_capture_mediaprojection",
            "pattern": r"MediaProjectionManager|MediaProjection|createVirtualDisplay|ImageReader",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"background"},
            "source": "mediaprojection",
        },
        {
            "category": "ndv_accessibility_surveillance",
            "pattern": r"AccessibilityService|getRootInActiveWindow|AccessibilityEvent",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"background"},
            "source": "accessibility",
        },
        {
            "category": "ndv_keylogging_like",
            "pattern": r"TYPE_VIEW_TEXT_CHANGED|TYPE_WINDOW_CONTENT_CHANGED",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"background"},
            "source": "accessibility_text",
        },
        {
            "category": "ndv_mic_eavesdropping",
            "pattern": r"AudioRecord|MediaRecorder|AudioSource\.MIC|AudioSource\.VOICE_CALL|AudioSource\.VOICE_COMMUNICATION",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "mic_record",
        },
        {
            "category": "ndv_camera_surveillance",
            "pattern": r"android\.hardware\.camera2|android\.hardware\.Camera",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "camera_api",
        },
        {
            "category": "ndv_geo_tracking_foreground",
            "pattern": r"android\.location\.LocationManager|FusedLocationProviderClient|getLastLocation|requestLocationUpdates",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "location_api",
        },
        {
            "category": "ndv_traffic_intercept_vpn",
            "pattern": r"android\.net\.VpnService|VpnService\$Builder|establish\(",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"network"},
            "source": "vpn_service",
        },
        {
            "category": "persist_workmanager_periodic",
            "pattern": r"PeriodicWorkRequest|enqueueUniquePeriodicWork",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"persistence", "background"},
            "source": "workmanager",
        },
        {
            "category": "persist_jobscheduler_periodic",
            "pattern": r"\.setPeriodic\(|\.setPersisted\(",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"persistence", "background"},
            "source": "jobscheduler",
        },
        {
            "category": "persist_alarmmanager_repeating",
            "pattern": r"\.setRepeating\(|\.setInexactRepeating\(|\.setExactAndAllowWhileIdle\(",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"persistence", "background"},
            "source": "alarmmanager",
        },
        {
            "category": "anomaly_frida_xposed_magisk_detection",
            "pattern": r"\b(frida|xposed|substrate|magisk|busybox|supersu|rootbeer|rootcloak)\b",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "analysis_evasion_tools",
        },
        {
            "category": "anomaly_emulator_detection",
            "pattern": (
                r"\b(goldfish|ranchu|genymotion|generic_x86|Andy|Droid4X|nox|bluestacks)\b"
                r"|Build\.(FINGERPRINT|HARDWARE|MODEL|PRODUCT|BOARD|BRAND|MANUFACTURER)"
                r"(?i:.*?(?:generic|sdk|emulator|vbox86|unknown))"
                r"|java\.vm\.name|000000000000000"
                r"|\b(?:isEmulator|detectEmulator|checkEmulator|isRunningOnEmulator)\b"
            ),
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "emulator_detection",
        },
        # --- Root detection ---
        {
            "category": "anomaly_root_detection",
            "pattern": r'/system/(?:bin|xbin)/(?:su|which)\b|/su\b|/data/local/tmp|Superuser\.apk|eu\.chainfire\.supersu|com\.topjohnwu\.magisk|RootTools|RootBeer|isDeviceRooted|checkForSuBinary',
            "targets": ("jadx",),
            "scope": "app",
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "root_detection",
        },
        # --- Anti-debug patterns ---
        {
            "category": "anomaly_anti_debug",
            "pattern": r'\bDebug\.isDebuggerConnected\b|\bTracerPid\b|\bandroid\.os\.Debug\b|ptrace\s*\(\s*PTRACE_TRACEME',
            "targets": ("jadx",),
            "scope": "app",
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "anti_debug",
        },
        # --- Weak cryptography ---
        {
            "category": "sec_weak_crypto",
            "pattern": r'Cipher\.getInstance\(\s*"(AES/ECB|DES|DESede|RC4|RC2|Blowfish)|MessageDigest\.getInstance\(\s*"(MD5|SHA-1)"',
            "targets": ("jadx",),
            "confidence": "C3",
            "evidence_type": "code",
            "tags": set(),
            "source": "weak_crypto",
        },
        # --- Predictable PRNG ---
        {
            "category": "sec_predictable_random",
            "pattern": r"SecureRandom.*\.setSeed\(\s*(System\.currentTimeMillis|System\.nanoTime|new\s+Date)",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "predictable_random",
        },
        # --- World-readable/writable files ---
        {
            "category": "sec_world_readable_writable",
            "pattern": r"MODE_WORLD_READABLE|MODE_WORLD_WRITABLE",
            "targets": ("jadx",),
            "confidence": "C3",
            "evidence_type": "code",
            "tags": set(),
            "source": "world_rw",
        },
        # --- Sensitive data on external storage ---
        {
            "category": "sec_external_storage_sensitive",
            "pattern": r"getExternalStorageDirectory|getExternalFilesDir",
            "targets": ("jadx",),
            "confidence": "C1",
            "evidence_type": "code",
            "tags": set(),
            "source": "external_storage",
        },
        # --- WebView JS eval ---
        {
            "category": "sec_webview_js_eval",
            "pattern": r'\.loadUrl\(\s*"javascript:|\.evaluateJavascript\(',
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "webview_js_eval",
        },
        # --- SQL injection ---
        {
            "category": "sec_sql_injection",
            "pattern": r'\.rawQuery\(\s*"[^"]*"\s*\+|\.execSQL\(\s*"[^"]*"\s*\+',
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "sql_injection",
        },
        # ContentProvider SQL injection: selection param concatenated into raw SQL
        {
            "category": "vul_content_provider_sql_injection",
            "pattern": r'"[^"]*"\s*\+\s*selection|selection\s*\+\s*"|rawQuery\([^)]*\+\s*(?:selection|sortOrder)',
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "content_provider_sqli",
        },
        # --- Sensitive data logging ---
        # C2: value is passed directly into log (variable or concatenation after keyword)
        # BUG-39: split into C2 (actual value logged) and C1 (concept mention)
        {
            "category": "sec_log_sensitive_data",
            "pattern": r"Log\.[dviwe]\([^)]*(?i)(password|passwd|token|secret|api.?key|credential)\s*[=+\[,]",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "log_sensitive_value",
        },
        # C1: keyword mentioned in log message (may be concept, not actual value)
        {
            "category": "sec_log_sensitive_data",
            "pattern": r"Log\.[dviwe]\([^)]*(?i)(password|passwd|token|secret|apikey|api_key|credential|ssn|credit.?card)",
            "targets": ("jadx",),
            "confidence": "C1",
            "evidence_type": "code",
            "tags": set(),
            "source": "log_sensitive",
        },
        # --- SharedPreferences + secrets ---
        {
            "category": "sec_sharedprefs_sensitive",
            "pattern": r"\.edit\(\)\.put(?:String|Int|Long)\([^)]*(?i)(password|token|secret|api.?key|private.?key|credential)",
            "targets": ("jadx",),
            "confidence": "C1",
            "evidence_type": "code",
            "tags": set(),
            "source": "sharedprefs_sensitive",
        },
        # --- SharedPreferences + secrets (split variable: editor.putString("key", ...)) ---
        {
            "category": "sec_sharedprefs_sensitive",
            "pattern": r'\.putString\(\s*"[^"]*(?i:password|token|secret|api.?key|private.?key|credential|encrypt)[^"]*"\s*,',
            "targets": ("jadx",),
            "scope": "app",
            "confidence": "C1",
            "evidence_type": "code",
            "tags": set(),
            "source": "sharedprefs_sensitive_split",
        },
        # --- Keyboard autocomplete cache on sensitive fields (BUG-29) ---
        # Detects password/sensitive fields missing inputType=textNoSuggestions or
        # IME_FLAG_NO_PERSONALIZED_LEARNING — keyboard caches input via autocomplete.
        {
            "category": "sec_keyboard_cache_sensitive",
            "pattern": (
                r'inputType\s*=\s*"(?!.*(?:textPassword|textVisiblePassword|numberPassword'
                r'|textNoSuggestions|textEmailAddress))[^"]*(?i:(?:user|login|email|account|name))[^"]*"'
            ),
            "targets": ("apktool",),
            "scope": "app_res",
            "confidence": "C1",
            "evidence_type": "resource",
            "tags": set(),
            "source": "keyboard_cache",
        },
        # --- SMS sending ---
        {
            "category": "ndv_sms_send",
            "pattern": r"SmsManager\.getDefault\(\)|\.sendTextMessage\(|\.sendMultipartTextMessage\(",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "sms_send",
        },
        # --- Device identifiers ---
        {
            "category": "ndv_device_identifiers",
            "pattern": r"\.getDeviceId\(|\.getImei\(|\.getSubscriberId\(|\.getLine1Number\(|\.getMeid\(|\.getSimSerialNumber\(",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "device_id",
        },
        # --- Contacts / CallLog / Calendar ---
        {
            "category": "ndv_contacts_access",
            "pattern": r"ContactsContract|CallLog\.Calls|CalendarContract",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "pii_access",
        },
        # --- Account enumeration ---
        {
            "category": "ndv_account_enumeration",
            "pattern": r"AccountManager\.get\(|\.getAccounts\(|\.getAccountsByType\(",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "account_enum",
        },
        # --- Installed apps enumeration ---
        {
            "category": "ndv_app_enumeration",
            "pattern": r"\.getInstalledPackages\(|\.getInstalledApplications\(",
            "targets": ("jadx",),
            "confidence": "C1",
            "evidence_type": "code",
            "tags": set(),
            "source": "app_enum",
        },
        # --- Wi-Fi fingerprinting ---
        {
            "category": "ndv_wifi_fingerprinting",
            "pattern": r"WifiManager.*\.getScanResults\(|\.getConnectionInfo\(",
            "targets": ("jadx",),
            "confidence": "C1",
            "evidence_type": "code",
            "tags": set(),
            "source": "wifi_fingerprint",
        },
        # --- Bluetooth enumeration ---
        {
            "category": "ndv_bluetooth_enumeration",
            "pattern": r"BluetoothAdapter.*\.getBondedDevices\(",
            "targets": ("jadx",),
            "confidence": "C1",
            "evidence_type": "code",
            "tags": set(),
            "source": "bt_enum",
        },
        # --- Device admin (only dangerous invocations, not mere registration) ---
        {
            "category": "ndv_device_admin",
            "pattern": r"\.lockNow\(|\.resetPassword\(|\.wipeData\(|BIND_DEVICE_ADMIN",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "device_admin",
        },
        # --- Certificate pinning (informational, not a vulnerability) ---
        {
            "category": "sec_certificate_pinning",
            "pattern": r'CertificatePinner|\.check\(\s*"[^"]+"\s*,\s*"sha256/',
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "cert_pinning",
        },
        # --- Proxy bypass ---
        {
            "category": "ndv_proxy_bypass",
            "pattern": r"Proxy\.NO_PROXY|\.proxy\(\s*Proxy\.NO_PROXY\s*\)",
            "targets": ("jadx",),
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "proxy_bypass",
        },
        # --- Hardcoded credentials (Java/Kotlin) ---
        {
            "category": "secret_hardcoded_credentials",
            "pattern": r'(?i)(?:password|passwd|pwd|passphrase|credentials?|secret|username|login|user_?name)\s*=\s*"[^"]{4,}"',
            "targets": ("jadx",),
            "scope": "app",
            "confidence": "C2",
            "evidence_type": "string",
            "tags": set(),
            "source": "hardcoded_creds",
        },
        # --- Hardcoded credentials (smali/resources) ---
        {
            "category": "secret_hardcoded_credentials",
            "pattern": r'(?i)(?:password|passwd|pwd|passphrase|default_?password|admin_?pass)\s*[:=]\s*["\x27](?!@|#ff|0x|android)[^\s"\']{4,}',
            "targets": ("apktool",),
            "scope": "app_res",
            "confidence": "C2",
            "evidence_type": "string",
            "tags": set(),
            "source": "hardcoded_creds_res",
        },
        # --- Dynamic BroadcastReceiver without permission ---
        {
            "category": "sec_broadcast_receiver_no_permission",
            "pattern": r"\.registerReceiver\(\s*\w+\s*,\s*(?:new\s+IntentFilter|\w+Filter)\s*\)",
            "targets": ("jadx",),
            "scope": "app",
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "broadcast_no_perm",
        },
        # --- Intent extras read (auxiliary, for correlation) ---
        {
            "category": "sec_intent_extra_read",
            "pattern": r"\.get(?:String|Int|Boolean|Long|Float|Double|Char|Short|Byte|Serializable|Parcelable)?Extra\(|\.getExtras\(\)",
            "targets": ("jadx",),
            "scope": "app",
            "confidence": "C1",
            "evidence_type": "code",
            "tags": set(),
            "source": "intent_extra_read",
        },
        # --- WebView JavaScript enabled ---
        {
            "category": "sec_webview_js_enabled",
            "pattern": r"\.setJavaScriptEnabled\(\s*true\s*\)",
            "targets": ("jadx",),
            "scope": "app",
            "confidence": "C1",
            "evidence_type": "code",
            "tags": set(),
            "source": "webview_js_enabled",
        },
        # --- Implicit broadcast without receiver restriction ---
        {
            "category": "sec_implicit_broadcast_send",
            "pattern": r"\bsendBroadcast\(\s*\w+\s*\)|\bsendOrderedBroadcast\(\s*\w+\s*,\s*null\s*\)",
            "targets": ("jadx",),
            "scope": "app",
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "implicit_broadcast",
        },
        # --- Cleartext HTTP protocol declaration ---
        {
            "category": "sec_cleartext_http_protocol",
            "pattern": r'(?i)\bprotocol\s*=\s*"http://"|new\s+HttpPost\(\s*"http://|new\s+URL\(\s*"http://|\.openConnection\(\s*"http://',
            "targets": ("jadx",),
            "scope": "app",
            "confidence": "C2",
            "evidence_type": "code",
            "tags": {"network", "mitm_enabler"},
            "source": "cleartext_http_protocol",
        },
        # --- Deprecated Apache HTTP client (no TLS guarantees) ---
        {
            "category": "sec_deprecated_http_client",
            "pattern": r"\bDefaultHttpClient\(\)|new\s+DefaultHttpClient\b|HttpClientBuilder\.create\(\)\.build\(\)",
            "targets": ("jadx",),
            "scope": "app",
            "confidence": "C1",
            "evidence_type": "code",
            "tags": {"network"},
            "source": "deprecated_http_client",
        },
        # --- Hardcoded crypto key (specific naming) ---
        {
            "category": "sec_hardcoded_crypto_key",
            "pattern": r'(?i)(?:secret.?key|crypto.?key|aes.?key|encryption.?key|signing.?key|hmac.?key)\s*=\s*"[^"]{8,}"|SecretKeySpec\(\s*"[^"]{8,}"\.getBytes',
            "targets": ("jadx",),
            "scope": "app",
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "hardcoded_crypto_key",
        },
        # --- Static/zero IV ---
        {
            "category": "sec_static_iv",
            "pattern": r'(?i)iv(?:Bytes|Spec|Parameter|_bytes)?\s*=\s*(?:\{(?:\s*0\s*,){7,}|new\s+byte\[\s*\d+\s*\]|"(?:0{16,}|00000000))',
            "targets": ("jadx",),
            "scope": "app",
            "confidence": "C2",
            "evidence_type": "code",
            "tags": set(),
            "source": "static_iv",
        },
        # --- Hardcoded key via field name "key" (broader, C1) ---
        {
            "category": "sec_hardcoded_crypto_key",
            "pattern": r'(?:String|byte\[\]|final)\s+key\s*=\s*"[^"]{16,}"',
            "targets": ("jadx",),
            "scope": "app",
            "confidence": "C1",
            "evidence_type": "code",
            "tags": set(),
            "source": "hardcoded_key_field",
        },
    ]
    STRINGS_PATTERN_STRINGS = {
        "secret_endpoints_hardcoded": r'(https?|wss?|ftp|grpc|grpcs|mqtts?|rtsp)://(?!schemas\.android\.com)[^" <>{}]{8,}',
        "secret_endpoints_ipv4": r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
        "ndv_dynamic_code_loading_dex": r"DexClassLoader|InMemoryDexClassLoader|PathClassLoader",
        "ndv_remote_command_shell": r"Runtime\.exec|ProcessBuilder",
    }
    STRINGS_CATEGORY_META = {
        "secret_endpoints_hardcoded": {"tags": {"network"}, "category": "secret_endpoints_hardcoded"},
        "secret_endpoints_ipv4": {"tags": {"network"}, "category": "secret_endpoints_hardcoded"},
        "ndv_dynamic_code_loading_dex": {"tags": {"dynamic_code"}, "category": "ndv_dynamic_code_loading_dex"},
        "ndv_remote_command_shell": {"tags": set(), "category": "ndv_remote_command_shell"},
    }
    YARA_RULE_CATEGORY = {
        "ANDROID_Remote_Command_MQTT_WS": ("ndv_remote_command", {"network"}),
        "ANDROID_Remote_Command_FCM": ("ndv_remote_command", {"network"}),
        "ANDROID_Geo_Tracking_Location_APIs": ("ndv_geo_tracking_foreground", set()),
        "ANDROID_Geo_Tracking_Persistence": ("ndv_geo_tracking_background", {"persistence", "background"}),
        "ANDROID_Eavesdropping_Microphone": ("ndv_mic_eavesdropping", set()),
        "ANDROID_Camera_Surveillance": ("ndv_camera_surveillance", set()),
        "ANDROID_Screen_Capture_MediaProjection": ("ndv_screen_capture_mediaprojection", {"background"}),
        "ANDROID_Accessibility_Screen_Observation": ("ndv_accessibility_surveillance", {"background"}),
        "ANDROID_Traffic_Interception_VPN_TUN": ("ndv_traffic_intercept_vpn", {"network"}),
        "ANDROID_TLS_TrustAll_or_MITM_Indicators": ("sec_tls_trust_all", {"mitm_enabler"}),
        "ANDROID_Combined_Spy_Profile_Strong": ("ndv_remote_command", {"network", "persistence", "background"}),
        "ANDROID_Device_Admin_Abuse": ("ndv_device_admin", set()),
        "ANDROID_Anti_Tamper_Signature_Check": ("anomaly_anti_tamper", set()),
    }

    LIB_DENYLIST_PREFIXES = (
        "com/google/", "androidx/", "android/support/",
        "kotlin/", "kotlinx/", "org/apache/",
        "com/squareup/", "io/reactivex/", "okhttp3/",
        "com/facebook/", "com/crashlytics/", "io/fabric/",
        "org/intellij/", "org/jetbrains/", "junit/",
        "com/bumptech/glide/", "com/jakewharton/",
        "org/bouncycastle/", "org/conscrypt/",
        "com/android/volley/", "retrofit2/",
        "io/grpc/", "com/fasterxml/", "org/json/",
    )

    def __init__(
        self,
        storage: Storage,
        timeout_sec: int = 600,
        on_progress=None,
        yara_rules_path: str | None = None,
    ):
        self.storage = storage
        self.timeout_sec = timeout_sec
        self.on_progress = on_progress
        self._run_dir: Path | None = None
        if yara_rules_path:
            self.yara_rules_path = Path(yara_rules_path).expanduser()
        else:
            self.yara_rules_path = (
                Path(__file__).resolve().parent / "yara" / "android_spy_triage.yar"
            )

    def _build_paths(self, run_dir: Path) -> Stage1Paths:
        artifacts_dir = run_dir / "artifacts"
        return Stage1Paths(
            run_dir=run_dir,
            logs_dir=run_dir / "logs",
            artifacts_dir=artifacts_dir,
            apktool_dir=artifacts_dir / "out_apktool",
            jadx_dir=artifacts_dir / "out_jadx",
            certs_dir=artifacts_dir / "certs",
        )

    def _build_logger(self, log_path: Path) -> Callable[[str], None]:
        def log(message: str) -> None:
            timestamp = datetime.now().isoformat(timespec="seconds")
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(f"{timestamp} {message}\n")

        return log

    def _prepare_run(self, run: Run, run_dir: Path, log: Callable[[str], None]) -> None:
        missing = self._check_tools()
        run.tools_checked = list(self.REQUIRED_TOOLS)
        run.tools_missing = missing
        if not missing:
            return
        error = f"Отсутствуют обязательные инструменты: {', '.join(missing)}"
        log(error)
        run.errors.append(error)
        run.status = "Error"
        run.finished_at = datetime.now().isoformat(timespec="seconds")
        self.storage.save_run(run, run_dir)
        raise RuntimeError(error)

    def _init_progress(
        self,
        apk_path: Path,
        paths: Stage1Paths,
        log: Callable[[str], None],
    ) -> PipelineState:
        cert_names = self._list_cert_entries(apk_path)
        so_count_estimate = self._count_zip_entries(apk_path, ".so")
        rg_step_count = self._rg_step_count(paths.apktool_dir.exists(), paths.jadx_dir.exists())
        # +1 for YARA, +1 for semgrep, +1 for checksec (if .so files present)
        total_steps = 12 + len(cert_names) + rg_step_count + so_count_estimate + 1 + (1 if so_count_estimate > 0 else 0)
        progress = ProgressTracker(
            runner=self,
            log=log,
            total_steps=total_steps,
            overall_start=time.monotonic(),
        )
        progress.emit()
        return PipelineState(
            cert_names=cert_names,
            so_count_estimate=so_count_estimate,
            rg_step_count=rg_step_count,
            progress=progress,
        )

    def _run_core_tools(
        self,
        apk_path: Path,
        logs_dir: Path,
        progress: ProgressTracker,
    ) -> list[CommandResult]:
        tasks = [
            ("Тип файла (file)", "file", ["file", str(apk_path)], "file"),
            ("Свойства файла (stat)", "stat", ["stat", str(apk_path)], "stat"),
            ("Контрольная сумма (sha256sum)", "sha256sum", ["sha256sum", str(apk_path)], "sha256sum"),
            (
                "Подпись APK (apksigner)",
                "apksigner",
                ["apksigner", "verify", "--verbose", "--print-certs", str(apk_path)],
                "apksigner",
            ),
            ("Манифест APK (aapt2)", "aapt2", ["aapt2", "dump", "badging", str(apk_path)], "aapt2"),
        ]
        results = []
        for label, tool, argv, log_label in tasks:
            results.append(
                progress.run_step(
                    label,
                    lambda tool=tool, argv=argv, log_label=log_label: self._run_tool(
                        tool,
                        argv,
                        logs_dir,
                        log_label,
                    ),
                )
            )
        return results

    def _run_cert_steps(
        self,
        apk_path: Path,
        paths: Stage1Paths,
        state: PipelineState,
        log: Callable[[str], None],
    ) -> list[CommandResult]:
        results: list[CommandResult] = []
        unzip_result = state.progress.run_step(
            "Список файлов APK (unzip)",
            lambda: self._run_tool(
                "unzip",
                ["unzip", "-l", str(apk_path)],
                paths.logs_dir,
                "unzip_list",
            ),
        )
        results.append(unzip_result)
        cert_list_result = state.progress.run_step(
            "Фильтрация сертификатов META-INF (grep)",
            lambda: self._run_tool(
                "grep",
                ["grep", "-E", self.CERT_LIST_PATTERN, str(Path(unzip_result.stdout_path))],
                paths.logs_dir,
                "certs_list",
            ),
        )
        results.append(cert_list_result)
        listed_certs = self._parse_cert_listing(Path(cert_list_result.stdout_path))
        state.cert_names = self._update_cert_names(listed_certs, state.cert_names, state.progress)
        cert_count = len(state.cert_names)

        extracted_certs = state.progress.run_step(
            "Извлечение сертификатов META-INF",
            lambda: self._extract_certs(apk_path, paths.certs_dir, log, state.cert_names),
        )
        self._update_step_estimate(
            "количество сертификатов",
            cert_count,
            len(extracted_certs),
            state.progress,
        )
        for index, cert_path in enumerate(extracted_certs, start=1):
            results.append(
                state.progress.run_step(
                    f"Сведения о сертификате ({index}/{len(extracted_certs)})",
                    lambda cert_path=cert_path, index=index: self._run_tool(
                        "keytool",
                        ["keytool", "-printcert", "-file", str(cert_path)],
                        paths.logs_dir,
                        f"keytool_{index}",
                    ),
                )
            )
        return results

    def _run_decompile_steps(
        self,
        apk_path: Path,
        paths: Stage1Paths,
        state: PipelineState,
    ) -> list[CommandResult]:
        results = []
        if paths.apktool_dir.exists():
            shutil.rmtree(paths.apktool_dir, ignore_errors=True)
        apktool_result = state.progress.run_step(
            "Декодирование ресурсов (apktool)",
            lambda: self._run_tool(
                "apktool",
                ["apktool", "d", "-f", "-o", str(paths.apktool_dir), str(apk_path)],
                paths.logs_dir,
                "apktool",
            ),
        )
        if self._log_contains(apktool_result, self.APKTOOL_FLEX_PATTERN):
            if paths.apktool_dir.exists():
                shutil.rmtree(paths.apktool_dir, ignore_errors=True)
            apktool_result = self._run_tool(
                "apktool",
                ["apktool", "d", "-f", "-r", "-o", str(paths.apktool_dir), str(apk_path)],
                paths.logs_dir,
                "apktool_nores",
            )
        results.append(apktool_result)
        results.append(
            state.progress.run_step(
                "Декомпиляция кода (jadx)",
                lambda: self._run_tool(
                    "jadx",
                    ["jadx", "-d", str(paths.jadx_dir), str(apk_path)],
                    paths.logs_dir,
                    "jadx",
                ),
            )
        )
        return results

    def _update_scan_estimates(self, paths: Stage1Paths, state: PipelineState) -> list[Path]:
        state.rg_step_count = self._update_step_estimate(
            "шаги rg",
            state.rg_step_count,
            self._rg_step_count(paths.apktool_dir.exists(), paths.jadx_dir.exists()),
            state.progress,
        )
        so_files = list(paths.apktool_dir.rglob("*.so"))
        state.so_count_estimate = self._update_step_estimate(
            "цели для strings",
            state.so_count_estimate,
            len(so_files),
            state.progress,
        )
        return so_files

    def _update_cert_names(
        self,
        listed_certs: list[str],
        cert_names: list[str],
        progress: ProgressTracker,
    ) -> list[str]:
        if not listed_certs:
            return cert_names
        if len(listed_certs) != len(cert_names):
            delta = len(listed_certs) - len(cert_names)
            progress.update_total_steps(
                progress.total_steps + delta,
                f"Обновлено количество сертификатов: {len(listed_certs)}",
            )
        return listed_certs

    def _update_step_estimate(
        self,
        label: str,
        previous_count: int,
        current_count: int,
        progress: ProgressTracker,
    ) -> int:
        if current_count != previous_count:
            delta = current_count - previous_count
            progress.update_total_steps(
                progress.total_steps + delta,
                f"Обновлено {label}: {current_count}",
            )
        return current_count

    def _run_pipeline(
        self,
        run: Run,
        paths: Stage1Paths,
        log: Callable[[str], None],
    ) -> tuple[list[Finding], list[CommandResult], ProgressTracker]:
        apk_path = Path(run.apk_path)
        state = self._init_progress(apk_path, paths, log)
        command_results: list[CommandResult] = []
        command_results.extend(self._run_core_tools(apk_path, paths.logs_dir, state.progress))
        command_results.extend(self._run_cert_steps(apk_path, paths, state, log))
        command_results.extend(self._run_decompile_steps(apk_path, paths, state))
        so_files = self._update_scan_estimates(paths, state)

        findings, finding_results = self._collect_findings(
            apktool_dir=paths.apktool_dir,
            jadx_dir=paths.jadx_dir,
            logs_dir=paths.logs_dir,
            run_dir=paths.run_dir,
            run_step=state.progress.run_step,
            so_files=so_files,
        )
        command_results.extend(finding_results)
        yara_result = state.progress.run_step(
            "YARA-сканирование",
            lambda: self._run_yara(paths.logs_dir, paths.apktool_dir, paths.jadx_dir, apk_path),
        )
        command_results.append(yara_result)
        findings.extend(self._yara_findings(paths.logs_dir, paths.run_dir))

        # semgrep — запускаем на JADX-выводе, если он есть
        _semgrep_t0 = time.monotonic()
        semgrep_findings = state.progress.run_step(
            "Semgrep-сканирование",
            lambda: self._run_semgrep_findings(paths),
        )
        findings.extend(semgrep_findings)
        if paths.jadx_dir.exists():
            _semgrep_dur = round(time.monotonic() - _semgrep_t0, 2)
            _semgrep_out = paths.run_dir / "tools" / "semgrep"
            command_results.append(CommandResult(
                tool="semgrep",
                argv=["semgrep"],
                cwd=str(paths.jadx_dir),
                return_code=0,
                duration_sec=_semgrep_dur,
                stdout_path=str(_semgrep_out / "results.json"),
                stderr_path=str(_semgrep_out / "semgrep.log"),
                status="success",
            ))

        # checksec — анализ .so библиотек
        _checksec_t0 = time.monotonic()
        if so_files:
            checksec_findings = state.progress.run_step(
                "checksec (.so библиотеки)",
                lambda: self._run_checksec_findings(paths, so_files),
            )
        else:
            checksec_findings = self._run_checksec_findings(paths, so_files)
        findings.extend(checksec_findings)
        if so_files:
            _checksec_dur = round(time.monotonic() - _checksec_t0, 2)
            _checksec_out = paths.run_dir / "tools" / "checksec"
            command_results.append(CommandResult(
                tool="checksec",
                argv=["checksec"],
                cwd=str(paths.apktool_dir),
                return_code=0,
                duration_sec=_checksec_dur,
                stdout_path=str(_checksec_out / "checksec_results.json"),
                stderr_path=str(_checksec_out / "checksec.log"),
                status="success",
            ))

        findings = self._post_process_findings(findings, paths.run_dir)
        SeverityEngine.apply(findings)

        return findings, command_results, state.progress

    def run(self, project_id: str) -> Run:
        run, run_dir = self.storage.create_run(project_id, STAGE_STATIC)
        self._run_dir = run_dir
        paths = self._build_paths(run_dir)
        log = self._build_logger(paths.logs_dir / "runner.log")
        self._prepare_run(run, run_dir, log)

        # Broad catch ensures run status and logs are updated even on unexpected failures.
        try:
            findings, command_results, progress = self._run_pipeline(run, paths, log)
            self._apply_result_statuses(run, command_results)

            run.command_results = command_results
            findings_path = self.storage.save_findings(run_dir, findings)
            run.findings_path = str(findings_path)
            run.status = "Done"
            run.finished_at = datetime.now().isoformat(timespec="seconds")

            report_manager = ReportManager(self.storage)
            _, html_path = progress.run_step(
                "Формирование отчётов",
                lambda: report_manager.generate_stage1(run, run_dir, findings),
            )
            run.report_path = str(html_path)
            report_manager.ensure_stub_reports(run, run_dir)

            self.storage.save_run(run, run_dir)
            progress.current_message = "Завершено"
            progress.emit()
            log("Этап 1 завершён.")
            return run
        except Exception as exc:  # pylint: disable=broad-exception-caught
            run.status = "Error"
            run.finished_at = datetime.now().isoformat(timespec="seconds")
            run.errors.append(f"Этап 1 завершился ошибкой: {exc}")
            log(traceback.format_exc())
            self.storage.save_run(run, run_dir)
            log(f"Этап 1 завершился ошибкой: {exc}")
            raise

    def _check_tools(self) -> list[str]:
        missing = []
        for tool in self.REQUIRED_TOOLS:
            if shutil.which(tool) is None:
                missing.append(tool)
        return missing

    def _apply_result_statuses(self, run: Run, command_results: list[CommandResult]) -> None:
        for result in command_results:
            result.status = self._classify_result(result)
            if result.status != "fail":
                continue
            if result.timed_out:
                run.errors.append(f"{result.tool}: превышено время ожидания")
            elif result.error:
                run.errors.append(f"{result.tool}: ошибка выполнения: {result.error}")
            else:
                run.errors.append(f"{result.tool}: код возврата {result.return_code}")

    def _classify_result(self, result: CommandResult) -> str:
        if result.timed_out or result.error:
            return "fail"
        if result.tool == "jadx" and self._is_jadx_partial(result):
            return "partial"
        allowed = {0, None}
        if result.tool in ("rg", "grep"):
            allowed.add(1)
        if result.return_code in allowed:
            return "success"
        return "fail"

    def _is_jadx_partial(self, result: CommandResult) -> bool:
        return self._log_contains(result, self.JADX_PARTIAL_PATTERN)

    def _log_contains(self, result: CommandResult, pattern: re.Pattern) -> bool:
        for path_str in (result.stdout_path, result.stderr_path):
            try:
                path = Path(path_str)
                if not path.exists():
                    continue
                if pattern.search(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except (OSError, UnicodeError):
                continue
        return False

    def _rg_step_count(self, apktool_exists: bool, jadx_exists: bool) -> int:
        targets = set()
        if apktool_exists:
            targets.add("apktool")
        if jadx_exists:
            targets.add("jadx")
        return sum(
            1
            for spec in self.RG_PATTERN_SPECS
            for target in spec["targets"]
            if target in targets
        )

    def _run_tool(
        self,
        tool: str,
        argv: list[str],
        logs_dir: Path,
        label: str,
    ):
        stdout_path = logs_dir / f"{label}.stdout.txt"
        stderr_path = logs_dir / f"{label}.stderr.txt"
        return run_command(
            tool=tool,
            argv=argv,
            cwd=str(logs_dir.parent),
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            timeout=self.timeout_sec,
        )

    def _run_yara(
        self,
        logs_dir: Path,
        apktool_dir: Path,
        jadx_dir: Path,
        apk_path: Path,
    ) -> CommandResult:
        rules_path = self.yara_rules_path
        _ = apk_path
        stdout_path = logs_dir / "yara.stdout.txt"
        stderr_path = logs_dir / "yara.stderr.txt"
        argv = ["yara", "-r", "-s", str(rules_path)]
        if not rules_path or not rules_path.is_file():
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text(
                f"Правила YARA не найдены: {rules_path}\n",
                encoding="utf-8",
            )
            return CommandResult(
                tool="yara",
                argv=argv,
                cwd=str(logs_dir.parent),
                return_code=None,
                duration_sec=0.0,
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
                error="rules_not_found",
            )
        targets = []
        for path in (apktool_dir, jadx_dir):
            if path.exists():
                targets.append(str(path))
        if not targets:
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            return CommandResult(
                tool="yara",
                argv=argv,
                cwd=str(logs_dir.parent),
                return_code=0,
                duration_sec=0.0,
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
            )
        # YARA 4.x accepts only ONE target (the last argument).
        # Previous arguments are treated as rule files.
        # Run YARA per directory and merge stdout.
        combined_stdout_parts: list[str] = []
        combined_stderr_parts: list[str] = []
        last_result = None
        for idx, target in enumerate(targets):
            label = f"yara_{idx}"
            result = self._run_tool("yara", argv + [target], logs_dir, label)
            last_result = result
            for part_list, path_attr in (
                (combined_stdout_parts, result.stdout_path),
                (combined_stderr_parts, result.stderr_path),
            ):
                try:
                    text = Path(path_attr).read_text(encoding="utf-8", errors="replace")
                    if text.strip():
                        part_list.append(text)
                except OSError:
                    pass
        stdout_path.write_text("\n".join(combined_stdout_parts), encoding="utf-8")
        stderr_path.write_text("\n".join(combined_stderr_parts), encoding="utf-8")
        if last_result is None:
            return CommandResult(
                tool="yara",
                argv=argv,
                cwd=str(logs_dir.parent),
                return_code=0,
                duration_sec=0.0,
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
            )
        return CommandResult(
            tool=last_result.tool,
            argv=argv + targets,
            cwd=last_result.cwd,
            return_code=last_result.return_code,
            duration_sec=last_result.duration_sec,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            error=last_result.error,
            timed_out=last_result.timed_out,
        )

    def _extract_certs(
        self,
        apk_path: Path,
        certs_dir: Path,
        log,
        cert_names: list[str] | None = None,
    ) -> list[Path]:
        certs_dir.mkdir(parents=True, exist_ok=True)
        extracted = []
        try:
            with zipfile.ZipFile(apk_path, "r") as handle:
                names = cert_names or handle.namelist()
                for name in names:
                    if not name.upper().startswith("META-INF/"):
                        continue
                    if not name.upper().endswith((".RSA", ".DSA", ".EC")):
                        continue
                    target = certs_dir / Path(name).name
                    with handle.open(name) as source, target.open("wb") as dest:
                        dest.write(source.read())
                    extracted.append(target)
        except (OSError, zipfile.BadZipFile, KeyError) as exc:
            log(f"Не удалось извлечь сертификаты: {exc}")
        return extracted

    @staticmethod
    def _is_lib_path(file_path: str) -> bool:
        """Return True if the file path points to a known third-party library."""
        for marker in ("sources/", "smali/"):
            idx = file_path.find(marker)
            if idx >= 0:
                relative = file_path[idx + len(marker):]
                for prefix in ("classes2/", "classes3/", "classes4/", "classes5/"):
                    if relative.startswith(prefix):
                        relative = relative[len(prefix):]
                        break
                if any(relative.startswith(p) for p in Stage1StaticRunner.LIB_DENYLIST_PREFIXES):
                    return True
        return False

    def _resolve_scope_targets(
        self,
        scope: str,
        label: str,
        base_target: Path,
        package_path: str,
    ) -> list[Path]:
        """Return rg target directories for the given scope."""
        if scope == "full" or not package_path:
            return [base_target]

        targets: list[Path] = []

        if label == "jadx":
            app_src = base_target / "sources" / package_path
            if app_src.exists():
                targets.append(app_src)
            if scope == "app_res":
                res_dir = base_target / "resources" / "res"
                if res_dir.exists():
                    targets.append(res_dir)
        elif label == "apktool":
            for child in base_target.iterdir():
                if child.is_dir() and child.name.startswith("smali"):
                    app_smali = child / package_path
                    if app_smali.exists():
                        targets.append(app_smali)
            if scope == "app_res":
                res_dir = base_target / "res"
                if res_dir.exists():
                    targets.append(res_dir)
                assets_dir = base_target / "assets"
                if assets_dir.exists():
                    targets.append(assets_dir)

        if not targets:
            targets.append(base_target)

        return targets

    def _collect_findings(
        self,
        apktool_dir: Path,
        jadx_dir: Path,
        logs_dir: Path,
        run_dir: Path,
        run_step,
        so_files: list[Path],
    ) -> tuple[list[Finding], list[CommandResult]]:
        findings: list[Finding] = []
        command_results = []
        manifest_findings, manifest_meta = self._manifest_findings(apktool_dir, run_dir, logs_dir)
        findings.extend(manifest_findings)
        findings.extend(self._apksigner_findings(logs_dir, run_dir, manifest_meta.get("target_sdk")))
        findings.extend(self._keytool_findings(logs_dir, run_dir))

        package_name = manifest_meta.get("package_name", "")
        package_path = package_name.replace(".", "/")

        rg_targets = {}
        if apktool_dir.exists():
            rg_targets["apktool"] = apktool_dir
        if jadx_dir.exists():
            rg_targets["jadx"] = jadx_dir
        else:
            # Emit a coverage warning finding so the analyst knows jadx-only rules
            # (dynamic code loading, WebView, TLS bypass, etc.) were not executed.
            jadx_only_categories = [
                spec["category"]
                for spec in self.RG_PATTERN_SPECS
                if tuple(spec.get("targets", ())) == ("jadx",)
            ]
            if jadx_only_categories:
                findings.append(
                    self._make_finding(
                        FindingSpec(
                            category="coverage_warning_jadx_unavailable",
                            evidence=(
                                f"jadx decompilation output not available; "
                                f"{len(jadx_only_categories)} rule(s) skipped: "
                                + ", ".join(jadx_only_categories[:10])
                                + ("..." if len(jadx_only_categories) > 10 else "")
                            ),
                            confidence="C1",
                            evidence_type="string",
                            tags={"coverage"},
                        ),
                        run_dir=run_dir,
                    )
                )

        for label, base_target in rg_targets.items():
            for spec in self.RG_PATTERN_SPECS:
                if label not in spec["targets"]:
                    continue
                scope = spec.get("scope", "app")
                scan_targets = self._resolve_scope_targets(scope, label, base_target, package_path)
                for idx, target in enumerate(scan_targets):
                    # Only the first target counts as a progress step.
                    effective_run_step = run_step if idx == 0 else (lambda _lbl, fn: fn())
                    rg_findings, result = self._rg_findings(
                        spec=spec,
                        target=target,
                        logs_dir=logs_dir,
                        run_dir=run_dir,
                        source=f"rg_{label}",
                        run_step=effective_run_step,
                    )
                    findings.extend(rg_findings)
                    command_results.append(result)

        if apktool_dir.exists():
            patterns = {
                category: re.compile(pattern)
                for category, pattern in self.STRINGS_PATTERN_STRINGS.items()
            }
            strings_findings, string_results = self._strings_findings(
                so_files=so_files,
                logs_dir=logs_dir,
                patterns=patterns,
                run_dir=run_dir,
                run_step=run_step,
            )
            findings.extend(strings_findings)
            command_results.extend(string_results)

        findings.extend(self._obfuscation_findings(jadx_dir, run_dir))
        return findings, command_results

    def _rg_findings(
        self,
        spec: dict,
        target: Path,
        logs_dir: Path,
        run_dir: Path,
        source: str,
        run_step,
    ) -> tuple[list[Finding], CommandResult]:
        category = spec["category"]
        pattern = spec["pattern"]
        # Include a short hash of the target path so that two runs of the same rule
        # against different scope-targets (e.g. app-scope vs full-scope) write to
        # distinct log files and do not overwrite each other.
        target_hash = hashlib.md5(str(target).encode()).hexdigest()[:8]
        label = f"rg_{category}_{source}_{target_hash}"
        progress_label = f"RG {category} ({source.replace('rg_', '')})"
        result = run_step(
            progress_label,
            lambda: self._run_tool(
                "rg",
                ["rg", "--vimgrep", "--no-messages", "--pcre2", "--", pattern, str(target)],
                logs_dir,
                label,
            ),
        )
        output_path = Path(result.stdout_path)
        findings = []
        if not output_path.exists():
            return findings, result

        confidence = spec.get("confidence", "C1")
        evidence_type = spec.get("evidence_type", "string")
        tags = set(spec.get("tags") or set())
        spec_source = spec.get("source", category)

        for line in output_path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split(":", 3)
            if len(parts) != 4:
                continue
            file_path, line_str, column_str, match = parts
            try:
                line_num = int(line_str)
                col_num = int(column_str)
            except ValueError:
                line_num = None
                col_num = None
            normalized_category = category
            if category == "secret_sensitive_kv":
                lowered = match.lower()
                if "password" in lowered or "passwd" in lowered or "pwd" in lowered:
                    normalized_category = "secret_password_like"
                else:
                    normalized_category = "secret_hardcoded_token_or_apikey"
            findings.append(
                self._make_finding(
                    FindingSpec(
                        category=normalized_category,
                        evidence=match.strip(),
                        file_path=file_path,
                        line=line_num,
                        column=col_num,
                        confidence=confidence,
                        evidence_type=evidence_type,
                        tags=tags,
                        sources=[f"rg:{spec_source}"],
                        source=f"rg:{spec_source}",
                    ),
                    run_dir=run_dir,
                )
            )
        return findings, result

    def _strings_findings(
        self,
        so_files: list[Path],
        logs_dir: Path,
        patterns: dict[str, re.Pattern],
        run_dir: Path,
        run_step,
    ) -> tuple[list[Finding], list[CommandResult]]:
        findings: list[Finding] = []
        results = []
        total_files = len(so_files)
        if not so_files:
            return findings, results
        scan_path = run_dir / "artifacts" / "strings_so_scan.txt"
        hits_path = run_dir / "artifacts" / "strings_so_rg_hits.txt"
        scan_path.parent.mkdir(parents=True, exist_ok=True)
        with scan_path.open("w", encoding="utf-8") as scan_handle, hits_path.open(
            "w", encoding="utf-8"
        ) as hits_handle:
            for index, so_file in enumerate(so_files, start=1):
                label = f"strings_{index}"
                progress_label = f"Strings ({index}/{total_files}): {so_file.name}"
                result = run_step(
                    progress_label,
                    lambda so_file=so_file, label=label: self._run_tool(
                        "strings",
                        ["strings", "-a", "-n", "8", str(so_file)],
                        logs_dir,
                        label,
                    ),
                )
                results.append(result)
                output_path = Path(result.stdout_path)
                if not output_path.exists():
                    continue
                try:
                    content = output_path.read_text(encoding="utf-8", errors="replace")
                except (OSError, UnicodeError):
                    content = ""
                if content:
                    scan_handle.write(f"### {so_file}\n")
                    scan_handle.write(content)
                    if not content.endswith("\n"):
                        scan_handle.write("\n")
                findings.extend(
                    self._scan_strings_output(
                        output_path,
                        patterns,
                        so_file,
                        run_dir,
                        hits_handle=hits_handle,
                    )
                )
        return findings, results

    def _scan_strings_output(
        self,
        output_path: Path,
        patterns: dict[str, re.Pattern],
        so_file: Path,
        run_dir: Path,
        hits_handle: TextIO | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for line_num, line in enumerate(
            output_path.read_text(encoding="utf-8", errors="replace").splitlines(),
            start=1,
        ):
            for category, regex in patterns.items():
                match = regex.search(line)
                if not match:
                    continue
                if hits_handle is not None:
                    hits_handle.write(f"{so_file}:{line_num}:{match.group(0)}\n")
                meta = self.STRINGS_CATEGORY_META.get(category, {"tags": set(), "category": category})
                normalized_category = meta["category"]
                findings.append(
                    self._make_finding(
                        FindingSpec(
                            category=normalized_category,
                            evidence=match.group(0),
                            file_path=str(so_file),
                            line=line_num,
                            column=None,
                            confidence="C1",
                            evidence_type="string",
                            tags=meta["tags"],
                            sources=[f"strings:{category}"],
                            source=f"strings:{category}",
                        ),
                        run_dir=run_dir,
                    )
                )
        return findings

    def _list_cert_entries(self, apk_path: Path) -> list[str]:
        try:
            with zipfile.ZipFile(apk_path, "r") as handle:
                return [
                    name
                    for name in handle.namelist()
                    if name.upper().startswith("META-INF/")
                    and name.upper().endswith((".RSA", ".DSA", ".EC"))
                ]
        except (OSError, zipfile.BadZipFile):
            return []

    def _parse_cert_listing(self, listing_path: Path) -> list[str]:
        if not listing_path.exists():
            return []
        pattern = re.compile(self.CERT_LIST_PATTERN, re.IGNORECASE)
        names: list[str] = []
        seen = set()
        for line in listing_path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = pattern.search(line)
            if not match:
                continue
            name = match.group(0)
            if name in seen:
                continue
            seen.add(name)
            names.append(name)
        return names

    def _count_zip_entries(self, apk_path: Path, suffix: str) -> int:
        try:
            with zipfile.ZipFile(apk_path, "r") as handle:
                return sum(1 for name in handle.namelist() if name.lower().endswith(suffix.lower()))
        except (OSError, zipfile.BadZipFile):
            return 0

    def _emit_progress(
        self,
        message: str,
        completed: int,
        total: int,
        elapsed_sec: float,
        eta_sec: int | None,
    ) -> None:
        if not self.on_progress:
            return
        payload = {
            "message": message,
            "completed": completed,
            "total": total,
            "elapsed_sec": elapsed_sec,
            "eta_sec": eta_sec,
        }
        if self._run_dir:
            payload["run_dir"] = str(self._run_dir)
        self.on_progress(payload)

    def _relative_path(self, file_path: str, run_dir: Path) -> str:
        path = Path(file_path)
        if not path.is_absolute():
            path = run_dir / path
        try:
            return str(path.resolve().relative_to(run_dir.resolve()))
        except (OSError, ValueError):
            return file_path

    def _make_finding(self, spec: FindingSpec, run_dir: Path | None = None) -> Finding:
        resolved_run_dir = run_dir or self._run_dir
        if resolved_run_dir is None:
            raise ValueError("run_dir is required to build a finding.")
        rel_path = self._relative_path(spec.file_path, resolved_run_dir) if spec.file_path else ""
        location = rel_path
        if spec.line is not None:
            location += f":{spec.line}"
            if spec.column is not None:
                location += f":{spec.column}"
        return Finding(
            category=spec.category,
            evidence=spec.evidence,
            match=spec.evidence,
            file_path=rel_path,
            line=spec.line,
            column=spec.column,
            confidence=spec.confidence,
            evidence_type=spec.evidence_type,
            tags=set(spec.tags or set()),
            sources=list(spec.sources or []),
            source=spec.source,
            location=location,
        )

    def _add_manifest_finding(
        self,
        findings: list[Finding],
        manifest_path: Path,
        run_dir: Path,
        category: str,
        evidence: str,
        tags: set[str] | None = None,
        sources: list[str] | None = None,
        confidence: str = "C3",
    ) -> None:
        findings.append(
            self._make_finding(
                FindingSpec(
                    category=category,
                    evidence=evidence,
                    file_path=str(manifest_path),
                    line=None,
                    column=None,
                    confidence=confidence,
                    evidence_type="manifest",
                    tags=tags or set(),
                    sources=sources or [],
                    source=None,
                ),
                run_dir=run_dir,
            )
        )

    def _manifest_permissions(self, root, ns: str) -> set[str]:
        permissions = set()
        for perm in root.findall("uses-permission") + root.findall("uses-permission-sdk-23"):
            name = perm.get(f"{ns}name") or perm.get("name")
            if name:
                permissions.add(name)
        return permissions

    def _manifest_target_sdk(self, root, ns: str) -> int | None:
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is None:
            return None
        target_sdk = uses_sdk.get(f"{ns}targetSdkVersion") or uses_sdk.get("targetSdkVersion")
        if target_sdk and target_sdk.isdigit():
            return int(target_sdk)
        return None

    def _manifest_app_flags(
        self,
        application,
        ns: str,
        target_sdk: int | None = None,
    ) -> tuple[bool, bool, bool, str | None, str | None, set[str]]:
        debuggable = False
        allow_backup = False
        uses_cleartext = False
        full_backup_content = None
        network_security_config = None
        foreground_types: set[str] = set()
        if application is None:
            return (
                debuggable,
                allow_backup,
                uses_cleartext,
                full_backup_content,
                network_security_config,
                foreground_types,
            )
        debuggable = (application.get(f"{ns}debuggable") or "false").lower() == "true"
        raw_backup = application.get(f"{ns}allowBackup")
        if raw_backup is None:
            # Android default: allowBackup=true for targetSdkVersion < 31 (API 31 = Android 12).
            allow_backup = target_sdk is None or target_sdk < 31
        else:
            allow_backup = raw_backup.lower() == "true"
        uses_cleartext = (application.get(f"{ns}usesCleartextTraffic") or "false").lower() == "true"
        full_backup_content = application.get(f"{ns}fullBackupContent")
        network_security_config = application.get(f"{ns}networkSecurityConfig")
        for service in application.findall("service"):
            fst = service.get(f"{ns}foregroundServiceType")
            if fst:
                for item in fst.split("|"):
                    foreground_types.add(item.strip())
        return (
            debuggable,
            allow_backup,
            uses_cleartext,
            full_backup_content,
            network_security_config,
            foreground_types,
        )

    @staticmethod
    def _xml_local_name(tag: str) -> str:
        return tag.rsplit("}", 1)[-1] if "}" in tag else tag

    def _resolve_xml_resource_path(self, apktool_dir: Path, resource_ref: str | None) -> Path | None:
        if not resource_ref:
            return None
        match = re.match(r"@(?:[\w.]+:)?xml/([A-Za-z0-9_.-]+)$", resource_ref.strip())
        if not match:
            return None
        return apktool_dir / "res" / "xml" / f"{match.group(1)}.xml"

    def _add_network_security_config_findings(
        self,
        findings: list[Finding],
        apktool_dir: Path,
        run_dir: Path,
        network_security_config_ref: str | None,
    ) -> None:
        nsc_path = self._resolve_xml_resource_path(apktool_dir, network_security_config_ref)
        if nsc_path is None or not nsc_path.exists():
            return

        try:
            tree = ET.parse(nsc_path)
            root = tree.getroot()
        except (ET.ParseError, OSError):
            return

        has_user_certs = False
        has_cleartext = False
        for elem in root.iter():
            tag = self._xml_local_name(elem.tag)
            if tag == "certificates" and (elem.get("src") or "").strip().lower() == "user":
                has_user_certs = True
            elif tag in {"base-config", "domain-config"}:
                cleartext = (elem.get("cleartextTrafficPermitted") or "").strip().lower()
                if cleartext == "true":
                    has_cleartext = True

        if has_user_certs:
            self._add_manifest_finding(
                findings,
                nsc_path,
                run_dir,
                "sec_network_security_config_weak",
                "networkSecurityConfig разрешает пользовательские CA (<certificates src=\"user\"/>)",
                tags={"mitm_enabler"},
                sources=["manifest:networkSecurityConfig:user_ca"],
            )
        if has_cleartext:
            self._add_manifest_finding(
                findings,
                nsc_path,
                run_dir,
                "sec_network_security_config_weak",
                "networkSecurityConfig разрешает cleartextTrafficPermitted=true",
                tags={"network", "mitm_enabler"},
                sources=["manifest:networkSecurityConfig:cleartext"],
            )

    def _add_manifest_permission_findings(
        self,
        findings: list[Finding],
        manifest_path: Path,
        run_dir: Path,
        permissions: set[str],
        foreground_types: set[str],
    ) -> None:
        def has_permission(name: str) -> bool:
            return name in permissions

        location_permissions = {
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
        }
        has_location = any(has_permission(perm) for perm in location_permissions)
        has_background_location = has_permission("android.permission.ACCESS_BACKGROUND_LOCATION")
        if "location" in foreground_types:
            has_background_location = True

        # NOTE: confidence="C2" for all permission-based NDV findings.
        # Manifest permission ≠ confirmed behaviour — app may declare but not use.
        if has_location:
            if has_background_location:
                self._add_manifest_finding(
                    findings,
                    manifest_path,
                    run_dir,
                    "ndv_geo_tracking_background",
                    "location permissions (background)",
                    tags={"background"},
                    sources=["manifest:permission:location"],
                    confidence="C2",
                )
            else:
                self._add_manifest_finding(
                    findings,
                    manifest_path,
                    run_dir,
                    "ndv_geo_tracking_foreground",
                    "location permissions",
                    sources=["manifest:permission:location"],
                    confidence="C2",
                )

        if has_permission("android.permission.RECORD_AUDIO"):
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "ndv_mic_eavesdropping",
                "android.permission.RECORD_AUDIO",
                sources=["manifest:permission:RECORD_AUDIO"],
                confidence="C2",
            )
        if has_permission("android.permission.CAMERA"):
            tags = {"background"} if "camera" in foreground_types else set()
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "ndv_camera_surveillance",
                "android.permission.CAMERA",
                tags=tags,
                sources=["manifest:permission:CAMERA"],
                confidence="C2",
            )
        if has_permission("android.permission.BIND_ACCESSIBILITY_SERVICE"):
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "ndv_accessibility_surveillance",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                tags={"background"},
                sources=["manifest:permission:BIND_ACCESSIBILITY_SERVICE"],
                confidence="C2",
            )
        if has_permission("android.permission.SYSTEM_ALERT_WINDOW"):
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "ndv_overlay_abuse",
                "android.permission.SYSTEM_ALERT_WINDOW",
                sources=["manifest:permission:SYSTEM_ALERT_WINDOW"],
                confidence="C2",
            )
        if has_permission("android.permission.READ_SMS") or has_permission("android.permission.RECEIVE_SMS"):
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "ndv_sms_intercept",
                "android.permission.READ_SMS/RECEIVE_SMS",
                sources=["manifest:permission:SMS"],
                confidence="C2",
            )
        if has_permission("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"):
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "ndv_notification_listener",
                "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
                sources=["manifest:permission:BIND_NOTIFICATION_LISTENER_SERVICE"],
                confidence="C2",
            )

        if "mediaProjection" in foreground_types:
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "ndv_screen_capture_mediaprojection",
                "foregroundServiceType=mediaProjection",
                tags={"background"},
                sources=["manifest:foregroundServiceType:mediaProjection"],
                confidence="C2",
            )

    def _component_exported(self, component, tag: str, ns: str) -> bool:
        exported = component.get(f"{ns}exported")
        if exported is not None:
            return exported.lower() == "true"
        has_intent = component.find("intent-filter") is not None
        return has_intent and tag in ("activity", "activity-alias", "service", "receiver")

    def _component_has_permission(self, component, ns: str) -> bool:
        attrs = [
            component.get(f"{ns}permission"),
            component.get(f"{ns}readPermission"),
            component.get(f"{ns}writePermission"),
        ]
        return any(attrs)

    def _component_has_deeplink(self, component, ns: str) -> bool:
        for intent_filter in component.findall("intent-filter"):
            has_view = any(
                (action.get(f"{ns}name") or "").endswith(".VIEW")
                or (action.get(f"{ns}name") == "android.intent.action.VIEW")
                for action in intent_filter.findall("action")
            )
            if not has_view:
                continue
            has_browsable = any(
                (cat.get(f"{ns}name") or "").endswith(".BROWSABLE")
                or (cat.get(f"{ns}name") == "android.intent.category.BROWSABLE")
                for cat in intent_filter.findall("category")
            )
            has_data = intent_filter.find("data") is not None
            if has_browsable or has_data:
                return True
        return False

    def _component_has_boot_completed(self, component, ns: str) -> bool:
        for intent_filter in component.findall("intent-filter"):
            for action in intent_filter.findall("action"):
                action_name = action.get(f"{ns}name") or ""
                if action_name == "android.intent.action.BOOT_COMPLETED":
                    return True
        return False

    def _add_manifest_component_findings(
        self,
        findings: list[Finding],
        manifest_path: Path,
        run_dir: Path,
        application,
        ns: str,
    ) -> None:
        if application is None:
            return
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for component in application.findall(tag):
                exported = self._component_exported(component, tag, ns)
                name = component.get(f"{ns}name") or component.get("name") or "unknown"
                if exported and not self._component_has_permission(component, ns):
                    _exp_category = (
                        "vul_exported_service_no_permission"
                        if tag == "service"
                        else "vul_exported_component_no_permission"
                    )
                    self._add_manifest_finding(
                        findings,
                        manifest_path,
                        run_dir,
                        _exp_category,
                        f"{tag}:{name} exported without permission",
                        tags={"exported"},
                        sources=[f"manifest:exported:{tag}"],
                    )
                if tag == "provider":
                    grant_uri = (component.get(f"{ns}grantUriPermissions") or "false").lower() == "true"
                    if exported or grant_uri:
                        self._add_manifest_finding(
                            findings,
                            manifest_path,
                            run_dir,
                            "vul_exported_provider_risky",
                            f"provider:{name} exported/grantUriPermissions",
                            tags={"exported"},
                            sources=["manifest:provider"],
                        )
                    if "FileProvider" in name and (exported or grant_uri):
                        self._add_manifest_finding(
                            findings,
                            manifest_path,
                            run_dir,
                            "vul_fileprovider_misconfig",
                            f"FileProvider:{name} exported/grantUriPermissions",
                            tags={"exported"},
                            sources=["manifest:fileprovider"],
                        )
                if tag in ("activity", "activity-alias") and exported:
                    if self._component_has_deeplink(component, ns):
                        self._add_manifest_finding(
                            findings,
                            manifest_path,
                            run_dir,
                            "vul_deeplink_intent_injection",
                            f"deeplink:{name} exported",
                            tags={"exported"},
                            sources=["manifest:deeplink"],
                        )
                if tag == "receiver" and self._component_has_boot_completed(component, ns):
                    self._add_manifest_finding(
                        findings,
                        manifest_path,
                        run_dir,
                        "persist_boot_completed",
                        f"receiver:{name} BOOT_COMPLETED",
                        tags={"persistence", "background"},
                        sources=["manifest:boot_completed"],
                    )
                if tag == "receiver":
                    # Map receiver actions to appropriate categories
                    _RECEIVER_ACTION_CATEGORY: dict[str, str] = {
                        "android.intent.action.PACKAGE_ADDED":    "ndv_package_monitoring",
                        "android.intent.action.PACKAGE_REMOVED":  "ndv_package_monitoring",
                        "android.intent.action.NEW_OUTGOING_CALL": "ndv_call_monitoring",
                        "android.telephony.action.PHONE_STATE_CHANGED": "ndv_call_monitoring",
                        "android.intent.action.PHONE_STATE": "ndv_call_monitoring",
                    }
                    for intent_filter in component.findall("intent-filter"):
                        for action in intent_filter.findall("action"):
                            action_name = action.get(f"{ns}name") or ""
                            category = _RECEIVER_ACTION_CATEGORY.get(action_name)
                            if category:
                                self._add_manifest_finding(
                                    findings,
                                    manifest_path,
                                    run_dir,
                                    category,
                                    f"receiver:{name} listens to {action_name}",
                                    tags={"background"},
                                    sources=["manifest:protected_broadcast"],
                                )
                                break
                if tag in ("activity", "activity-alias") and exported:
                    launch_mode = component.get(f"{ns}launchMode") or ""
                    task_affinity = component.get(f"{ns}taskAffinity")
                    if launch_mode == "singleTask" and task_affinity != "":
                        self._add_manifest_finding(
                            findings,
                            manifest_path,
                            run_dir,
                            "vul_task_hijacking",
                            f"activity:{name} singleTask exported without taskAffinity=\"\"",
                            tags={"exported"},
                            sources=["manifest:task_hijacking"],
                        )
                    exclude_from_recents = (
                        component.get(f"{ns}excludeFromRecents") or "false"
                    ).lower() == "true"
                    if exclude_from_recents:
                        self._add_manifest_finding(
                            findings,
                            manifest_path,
                            run_dir,
                            "vul_exported_component_no_permission",
                            f"activity:{name} exported + excludeFromRecents (hidden from user)",
                            tags={"exported"},
                            sources=["manifest:exclude_from_recents"],
                        )
                if tag == "service":
                    perm = component.get(f"{ns}permission") or ""
                    if perm == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE":
                        self._add_manifest_finding(
                            findings,
                            manifest_path,
                            run_dir,
                            "ndv_notification_listener",
                            f"service:{name} notification listener",
                            sources=["manifest:notification_listener_service"],
                        )

    def _manifest_findings(
        self,
        apktool_dir: Path,
        run_dir: Path,
        logs_dir: Path,
    ) -> tuple[list[Finding], dict]:
        findings: list[Finding] = []
        manifest_path = apktool_dir / "AndroidManifest.xml"
        meta = {"target_sdk": None, "permissions": set()}
        if not manifest_path.exists():
            meta.update(self._parse_aapt2_info(logs_dir))
            return findings, meta

        ns = "{http://schemas.android.com/apk/res/android}"
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
        except (ET.ParseError, OSError):
            meta.update(self._parse_aapt2_info(logs_dir))
            return findings, meta
        meta["package_name"] = root.get("package") or ""
        permissions = self._manifest_permissions(root, ns)
        meta["permissions"] = permissions
        target_sdk = self._manifest_target_sdk(root, ns)
        if target_sdk is not None:
            meta["target_sdk"] = target_sdk

        application = root.find("application")
        (
            debuggable,
            allow_backup,
            uses_cleartext,
            full_backup_content,
            network_security_config,
            foreground_types,
        ) = self._manifest_app_flags(application, ns, target_sdk=target_sdk)

        if debuggable:
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "vul_debuggable_true",
                "android:debuggable=true",
                sources=["manifest:debuggable"],
            )
        if allow_backup:
            evidence = "android:allowBackup=true"
            if not full_backup_content:
                evidence += " (fullBackupContent missing)"
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "vul_backup_enabled",
                evidence,
                sources=["manifest:allowBackup"],
            )
        if target_sdk is not None and target_sdk >= 31 and application is not None:
            data_extraction_rules = application.get(f"{ns}dataExtractionRules")
            if not data_extraction_rules:
                self._add_manifest_finding(
                    findings,
                    manifest_path,
                    run_dir,
                    "sec_backup_data_extraction_rules",
                    "android:dataExtractionRules missing (targetSdk >= 31)",
                    sources=["manifest:dataExtractionRules"],
                )
        if uses_cleartext:
            self._add_manifest_finding(
                findings,
                manifest_path,
                run_dir,
                "sec_cleartext_traffic_allowed",
                "android:usesCleartextTraffic=true",
                tags={"mitm_enabler", "network"},
                sources=["manifest:usesCleartextTraffic"],
            )
        self._add_network_security_config_findings(
            findings,
            apktool_dir,
            run_dir,
            network_security_config,
        )

        self._add_manifest_permission_findings(
            findings,
            manifest_path,
            run_dir,
            permissions,
            foreground_types,
        )
        self._add_manifest_component_findings(
            findings,
            manifest_path,
            run_dir,
            application,
            ns,
        )

        meta.update(self._parse_aapt2_info(logs_dir))
        return findings, meta

    def _parse_aapt2_info(self, logs_dir: Path) -> dict:
        info: dict = {}
        stdout_path = logs_dir / "aapt2.stdout.txt"
        if not stdout_path.exists():
            return info
        text = stdout_path.read_text(encoding="utf-8", errors="replace")
        match = re.search(r"targetSdkVersion:'(\d+)'", text)
        if match:
            info["target_sdk"] = int(match.group(1))
        match = re.search(r"package:\s*name='([^']+)'", text)
        if match:
            info["package_name"] = match.group(1)
        match = re.search(r"minSdkVersion:'(\d+)'", text)
        if match:
            info["min_sdk"] = int(match.group(1))
        return info

    def _apksigner_findings(
        self,
        logs_dir: Path,
        run_dir: Path,
        target_sdk: int | None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        stdout_path = logs_dir / "apksigner.stdout.txt"
        stderr_path = logs_dir / "apksigner.stderr.txt"
        if not stdout_path.exists() and not stderr_path.exists():
            return findings
        text = ""
        if stdout_path.exists():
            text += stdout_path.read_text(encoding="utf-8", errors="replace")
        if stderr_path.exists():
            text += "\n" + stderr_path.read_text(encoding="utf-8", errors="replace")

        rel_path = self._relative_path(str(stdout_path), run_dir)

        if re.search(r"DOES NOT VERIFY|ERROR", text, re.IGNORECASE):
            findings.append(
                self._make_finding(
                    FindingSpec(
                        category="supplychain_signature_invalid",
                        evidence="Проверка apksigner завершилась ошибкой",
                        file_path=rel_path,
                        line=None,
                        column=None,
                        confidence="C3",
                        evidence_type="signing",
                        tags=set(),
                        sources=["apksigner:verify"],
                        source="apksigner:verify",
                    ),
                    run_dir=run_dir,
                )
            )

        if "Android Debug" in text:
            findings.append(
                self._make_finding(
                    FindingSpec(
                        category="supplychain_debug_certificate",
                        evidence="Сертификат Android Debug",
                        file_path=rel_path,
                        line=None,
                        column=None,
                        confidence="C3",
                        evidence_type="signing",
                        tags=set(),
                        sources=["apksigner:debug_cert"],
                        source="apksigner:debug_cert",
                    ),
                    run_dir=run_dir,
                )
            )

        v1 = self._parse_apksigner_bool(text, "1")
        v2 = self._parse_apksigner_bool(text, "2")
        v3 = self._parse_apksigner_bool(text, "3")
        if target_sdk is not None and target_sdk >= 24 and v1 and not v2 and not v3:
            findings.append(
                self._make_finding(
                    FindingSpec(
                        category="supplychain_signature_scheme_v1_only",
                        evidence="Используется только схема подписи v1",
                        file_path=rel_path,
                        line=None,
                        column=None,
                        confidence="C3",
                        evidence_type="signing",
                        tags=set(),
                        sources=["apksigner:scheme"],
                        source="apksigner:scheme",
                    ),
                    run_dir=run_dir,
                )
            )

        return findings

    def _parse_apksigner_bool(self, text: str, scheme: str) -> bool:
        pattern = re.compile(rf"Verified using v{scheme} scheme.*?:\s*(true|false)", re.IGNORECASE)
        match = pattern.search(text)
        if not match:
            return False
        return match.group(1).lower() == "true"

    def _keytool_findings(self, logs_dir: Path, run_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in sorted(logs_dir.glob("keytool_*.stdout.txt")):
            text = path.read_text(encoding="utf-8", errors="replace")
            rel_path = self._relative_path(str(path), run_dir)
            if re.search(r"CN=Android Debug", text):
                findings.append(
                    self._make_finding(
                        FindingSpec(
                            category="supplychain_debug_certificate",
                            evidence="Сертификат Android Debug",
                            file_path=rel_path,
                            line=None,
                            column=None,
                            confidence="C3",
                            evidence_type="signing",
                            tags=set(),
                            sources=[f"keytool:{path.name}"],
                            source=f"keytool:{path.name}",
                        ),
                        run_dir=run_dir,
                    )
                )
            expired = self._keytool_cert_expired(text)
            if expired:
                findings.append(
                    self._make_finding(
                        FindingSpec(
                            category="supplychain_cert_expired",
                            evidence="Срок действия сертификата истёк",
                            file_path=rel_path,
                            line=None,
                            column=None,
                            confidence="C3",
                            evidence_type="signing",
                            tags=set(),
                            sources=[f"keytool:{path.name}"],
                            source=f"keytool:{path.name}",
                        ),
                        run_dir=run_dir,
                    )
                )
        return findings

    def _keytool_cert_expired(self, text: str) -> bool:
        match = re.search(r"Valid from:\s*(.+?)\s*until:\s*(.+)", text)
        if not match:
            return False
        until_raw = match.group(2).strip()
        for fmt in ("%a %b %d %H:%M:%S %Z %Y", "%a %b %d %H:%M:%S %Y"):
            try:
                until = datetime.strptime(until_raw, fmt)
                if until.tzinfo is None:
                    until = until.replace(tzinfo=timezone.utc)
                return until < datetime.now(timezone.utc)
            except ValueError:
                continue
        return False

    def _yara_findings(self, logs_dir: Path, run_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        stdout_path = logs_dir / "yara.stdout.txt"
        if not stdout_path.exists():
            return findings
        for line in stdout_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            # Skip string-match-detail lines (format: 0xOFFSET:$STRING_ID: matched_data).
            first_token = line.split(maxsplit=1)[0]
            if ":" in first_token:
                continue
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                continue
            rule_name, file_path = parts[0].strip(), parts[1].strip()
            # Valid YARA rule name: letters, digits, underscore.
            if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', rule_name):
                continue
            mapping = self.YARA_RULE_CATEGORY.get(rule_name)
            if mapping:
                category, tags = mapping
            else:
                # Fallback for custom/unknown YARA rules.
                category = f"yara_unknown_{rule_name.lower()}"
                tags = set()
            finding_confidence = "C2"
            finding_tags = set(tags)
            if self._is_lib_path(file_path):
                finding_tags.add("lib_noise")
                finding_confidence = "C1"
            findings.append(
                self._make_finding(
                    FindingSpec(
                        category=category,
                        evidence=rule_name,
                        file_path=file_path,
                        line=None,
                        column=None,
                        confidence=finding_confidence,
                        evidence_type="code",
                        tags=finding_tags,
                        sources=[f"yara:{rule_name}"],
                        source=f"yara:{rule_name}",
                    ),
                    run_dir=run_dir,
                )
            )
        return findings

    def _obfuscation_findings(self, jadx_dir: Path, run_dir: Path) -> list[Finding]:
        sources_dir = jadx_dir / "sources"
        if not sources_dir.exists():
            return []
        java_files = list(sources_dir.rglob("*.java")) + list(sources_dir.rglob("*.kt"))
        if len(java_files) < 50:
            return []
        short_names = [path for path in java_files if len(path.stem) <= 2]
        ratio = len(short_names) / max(1, len(java_files))
        if ratio < 0.4:
            return []
        evidence = f"short class names ratio {ratio:.2f} ({len(short_names)}/{len(java_files)})"
        return [
            self._make_finding(
                FindingSpec(
                    category="anomaly_obfuscation_heavy",
                    evidence=evidence,
                    file_path=str(sources_dir),
                    line=None,
                    column=None,
                    confidence="C2",
                    evidence_type="code",
                    tags=set(),
                    sources=["jadx:obfuscation"],
                    source="jadx:obfuscation",
                ),
                run_dir=run_dir,
            )
        ]

    def _post_process_findings(self, findings: list[Finding], run_dir: Path) -> list[Finding]:
        findings = self._aggregate_reflection_findings(findings, run_dir)
        findings = self._apply_download_execute(findings, run_dir)
        findings.extend(self._correlate_payload_decode_load(findings, run_dir))
        findings = self._apply_persistence_boost(findings)
        findings = self._apply_combo_boosts(findings)
        findings.extend(self._extract_cleartext_http_findings(findings, run_dir))
        findings.extend(self._correlate_intent_injection(findings, run_dir))
        findings.extend(self._correlate_webview_file_xss(findings, run_dir))
        findings = self._strip_internal_signal_findings(findings)
        return self._dedupe_findings(findings)

    def _extract_cleartext_http_findings(self, findings: list[Finding], run_dir: Path) -> list[Finding]:
        """Extract http:// endpoints from secret_endpoints_hardcoded into a separate category."""
        from urllib.parse import urlparse

        NOISE_HOSTS = {
            "localhost", "127.0.0.1", "10.0.2.2", "10.0.3.2",
            "0.0.0.0", "example.com", "example.org",
            "schemas.android.com", "www.w3.org",
            "ns.adobe.com", "xmlpull.org",
        }
        new_findings: list[Finding] = []
        for f in findings:
            if f.category != "secret_endpoints_hardcoded":
                continue
            evidence = (f.evidence or f.match or "").strip()
            if not evidence.startswith("http://"):
                continue
            try:
                host = urlparse(evidence).hostname or ""
            except Exception:
                continue
            if host.lower() in NOISE_HOSTS:
                continue
            try:
                if ipaddress.ip_address(host).is_private:
                    continue
            except ValueError:
                pass  # not an IP address, continue with host-based check
            new_findings.append(
                self._make_finding(
                    FindingSpec(
                        category="sec_cleartext_http_endpoint",
                        evidence=evidence,
                        file_path=f.file_path or "",
                        line=f.line,
                        column=f.column,
                        confidence="C2",
                        evidence_type="string",
                        tags={"network", "mitm_enabler"},
                        sources=f.sources or ["rg:endpoint_url"],
                        source=f.source,
                    ),
                    run_dir=run_dir,
                )
            )
        return new_findings

    def _correlate_intent_injection(self, findings: list[Finding], run_dir: Path) -> list[Finding]:
        """Exported component + getStringExtra in the same class -> intent injection indicator.

        Matching uses the full class FQN converted to a path suffix (e.g.
        ``com.example.MainActivity`` → ``com/example/MainActivity``) so that
        inner-class names (``Outer$Inner``), Kotlin-mangled files, and multi-class
        files are handled correctly — rather than relying on ``Path.stem`` which
        only captures the last path component and fails on nested/mangled names.
        """
        # Map short_name → path_suffix for all exported components.
        # Strip anonymous/inner class suffixes before converting to path:
        # "com.example.Outer$Inner" → base "com.example.Outer" → "com/example/Outer"
        exported_path_suffixes: list[str] = []
        for f in findings:
            if f.category != "vul_exported_component_no_permission":
                continue
            evidence = f.evidence or ""
            if ":" in evidence:
                class_fqn = evidence.split(":")[1].split()[0]
                base_fqn = class_fqn.split("$")[0]  # strip inner/anon class suffix
                path_suffix = base_fqn.replace(".", "/")
                exported_path_suffixes.append(path_suffix)

        if not exported_path_suffixes:
            return []

        new_findings: list[Finding] = []
        for f in findings:
            if f.category != "sec_intent_extra_read":
                continue
            file_path = (f.file_path or "").replace("\\", "/")
            matched = any(
                file_path.endswith(ps + ".java")
                or file_path.endswith(ps + ".kt")
                or file_path.endswith(ps + ".smali")
                for ps in exported_path_suffixes
            )
            if matched:
                # Derive a display name from the matched path suffix for the evidence string.
                matched_suffix = next(
                    ps for ps in exported_path_suffixes
                    if file_path.endswith(ps + ".java")
                    or file_path.endswith(ps + ".kt")
                    or file_path.endswith(ps + ".smali")
                )
                class_display = matched_suffix.rsplit("/", 1)[-1]
                new_findings.append(
                    self._make_finding(
                        FindingSpec(
                            category="sec_intent_injection_in_exported",
                            evidence=f"Экспортируемый компонент {class_display}: extras из Intent читаются без валидации",
                            file_path=f.file_path or "",
                            line=f.line,
                            column=f.column,
                            confidence="C2",
                            evidence_type="code",
                            tags={"exported"},
                            sources=["correlation:exported+extras"],
                            source="correlation:exported+extras",
                        ),
                        run_dir=run_dir,
                    )
                )
        return new_findings

    def _correlate_webview_file_xss(self, findings: list[Finding], run_dir: Path) -> list[Finding]:
        """WebView JS enabled + external storage file:// loadUrl → XSS risk."""
        has_js_enabled = any(f.category == "sec_webview_js_enabled" for f in findings)
        has_file_url = any(
            f.category == "sec_external_storage_sensitive"
            and "loadUrl" in (f.evidence or f.match or "")
            for f in findings
        )
        if not (has_js_enabled and has_file_url):
            return []
        js_finding = next(f for f in findings if f.category == "sec_webview_js_enabled")
        return [
            self._make_finding(
                FindingSpec(
                    category="sec_webview_file_xss",
                    evidence="В WebView включён JavaScript и используется loadUrl(file://) из внешнего хранилища",
                    file_path=js_finding.file_path or "",
                    line=js_finding.line,
                    column=js_finding.column,
                    confidence="C2",
                    evidence_type="code",
                    tags=set(),
                    sources=["correlation:webview_js+file_url"],
                    source="correlation:webview_js+file_url",
                ),
                run_dir=run_dir,
            )
        ]

    def _correlate_payload_decode_load(self, findings: list[Finding], run_dir: Path) -> list[Finding]:
        """Decode/decrypt signal + dynamic DEX loading in the same file -> staged payload."""
        decode_hits = [f for f in findings if f.category == "signal_payload_decode"]
        if not decode_hits:
            return []

        loader_by_path: dict[str, Finding] = {}
        for finding in findings:
            if finding.category == "ndv_dynamic_code_loading_dex" and finding.file_path:
                loader_by_path.setdefault(finding.file_path, finding)
        if not loader_by_path:
            return []

        new_findings: list[Finding] = []
        emitted_paths: set[str] = set()
        for decode in decode_hits:
            file_path = decode.file_path or ""
            if not file_path or file_path not in loader_by_path or file_path in emitted_paths:
                continue
            loader = loader_by_path[file_path]
            emitted_paths.add(file_path)
            new_findings.append(
                self._make_finding(
                    FindingSpec(
                        category="ndv_payload_decode_load",
                        evidence="Обнаружены декодирование/расшифровка payload и динамическая загрузка DEX в одном файле",
                        file_path=file_path,
                        line=loader.line or decode.line,
                        column=loader.column or decode.column,
                        confidence="C2",
                        evidence_type="code",
                        tags={"dynamic_code"},
                        sources=["correlation:payload_decode+dex_loader"],
                        source="correlation:payload_decode+dex_loader",
                    ),
                    run_dir=run_dir,
                )
            )
        return new_findings

    def _aggregate_reflection_findings(self, findings: list[Finding], run_dir: Path) -> list[Finding]:
        reflection = [finding for finding in findings if finding.category == "ndv_reflection_heavy"]
        if not reflection:
            return findings
        if len(reflection) < 5:
            return findings  # keep as-is; too few to aggregate but still worth reporting
        sample = reflection[0]
        aggregated = self._make_finding(
            FindingSpec(
                category="ndv_reflection_heavy",
                evidence=f"Количество вызовов рефлексии: {len(reflection)}",
                file_path=sample.file_path,
                line=None,
                column=None,
                confidence=sample.confidence or "C2",
                evidence_type=sample.evidence_type or "code",
                tags=set(sample.tags),
                sources=sample.sources or ["rg:reflection"],
                source=sample.source,
            ),
            run_dir=run_dir,
        )
        remaining = [f for f in findings if f.category != "ndv_reflection_heavy"]
        remaining.append(aggregated)
        return remaining

    def _apply_download_execute(self, findings: list[Finding], run_dir: Path) -> list[Finding]:
        downloads = [f for f in findings if f.category == "signal_download_manager"]
        if not downloads:
            return findings
        code_exec = [
            f
            for f in findings
            if f.category
            in (
                "ndv_dynamic_code_loading_dex",
                "ndv_native_code_loader_suspicious",
                "ndv_remote_command",
                "ndv_remote_command_shell",
            )
        ]
        if not code_exec:
            return [f for f in findings if f.category != "signal_download_manager"]
        combined = []
        for hit in downloads:
            combined.append(
                self._make_finding(
                    FindingSpec(
                        category="ndv_download_execute",
                        evidence="DownloadManager в сочетании с динамической загрузкой кода",
                        file_path=hit.file_path or "",
                        line=hit.line,
                        column=hit.column,
                        confidence="C2",
                        evidence_type="code",
                        tags={"network", "dynamic_code"},
                        sources=hit.sources or ["rg:download_manager"],
                        source=hit.source,
                    ),
                    run_dir=run_dir,
                )
            )
        filtered = [f for f in findings if f.category != "signal_download_manager"]
        filtered.extend(combined)
        return filtered

    def _strip_internal_signal_findings(self, findings: list[Finding]) -> list[Finding]:
        return [f for f in findings if not f.category.startswith("signal_")]

    # Category prefixes that are semantically related to persistent malicious behaviour
    # and should receive the "persistence" context tag when a persistence mechanism
    # is detected in the app.  Vulnerability / transport findings (sec_*, vul_*) are
    # intentionally excluded — tagging them with "persistence" is misleading.
    _PERSISTENCE_TAGGABLE_PREFIXES = ("ndv_", "backdoor_", "anomaly_", "secret_")

    def _apply_persistence_boost(self, findings: list[Finding]) -> list[Finding]:
        persistence_categories = {
            "persist_boot_completed",
            "persist_workmanager_periodic",
            "persist_jobscheduler_periodic",
            "persist_alarmmanager_repeating",
        }
        # Apply persistence boost only when app-scope findings trigger it.
        has_persistence = any(
            f.category in persistence_categories
            and "lib_noise" not in (f.tags or set())
            and not self._is_lib_path(f.file_path or "")
            for f in findings
        )
        if not has_persistence:
            return findings
        for finding in findings:
            if finding.category in persistence_categories:
                continue
            if any(
                source.startswith("rg:endpoint_")
                for source in (finding.sources or [])
            ):
                continue
            # Do not add persistence tag to findings from library code.
            if self._is_lib_path(finding.file_path or ""):
                continue
            # Only tag categories that are semantically related to persistent
            # malicious behaviour; skip vulnerability / transport findings.
            if not any(
                finding.category.startswith(p) for p in self._PERSISTENCE_TAGGABLE_PREFIXES
            ):
                continue
            finding.tags.add("persistence")
        return findings

    def _apply_combo_boosts(self, findings: list[Finding]) -> list[Finding]:
        """Increase confidence when confirming combinations are present.

        Uses model_copy() to produce new Finding objects instead of mutating
        existing ones, making this method idempotent and side-effect-free.
        """
        categories = {f.category for f in findings}
        has_persistence = bool(
            categories
            & {
                "persist_boot_completed",
                "persist_workmanager_periodic",
                "persist_jobscheduler_periodic",
                "persist_alarmmanager_repeating",
            }
        )
        has_network = any("network" in (f.tags or set()) for f in findings)

        combos = [
            ("ndv_mic_eavesdropping", has_persistence),
            ("ndv_camera_surveillance", has_persistence),
            ("ndv_geo_tracking_background", has_persistence),
            ("ndv_keylogging_like", has_network),
            ("ndv_dynamic_code_loading_dex", has_network),
            ("ndv_traffic_intercept_vpn", "sec_tls_trust_all" in categories),
        ]
        result: list[Finding] = []
        for finding in findings:
            upgraded = finding
            for target_cat, condition in combos:
                if finding.category == target_cat and condition:
                    if finding.confidence in ("C1", "C2"):
                        upgraded = finding.model_copy(update={
                            "confidence": "C3",
                            "tags": finding.tags | {"combo_confirmed"},
                        })
                        break
            result.append(upgraded)
        return result

    def _dedupe_findings(self, findings: list[Finding]) -> list[Finding]:
        seen: set[tuple] = set()
        deduped: list[Finding] = []
        # First pass: collect all sources per signing category so that when
        # apksigner and keytool both report the same issue we keep one Finding
        # with merged provenance rather than two identical-looking entries.
        signing_sources: dict[str, list[str]] = {}
        for finding in findings:
            if finding.evidence_type == "signing":
                signing_sources.setdefault(finding.category, []).extend(
                    finding.sources or []
                )

        signing_emitted: set[str] = set()
        for finding in findings:
            if finding.evidence_type == "signing":
                # Semantic key for signing: category only (same cert issue from
                # apksigner and keytool is one finding, not two).
                if finding.category in signing_emitted:
                    continue
                signing_emitted.add(finding.category)
                merged_sources = list(dict.fromkeys(signing_sources.get(finding.category, [])))
                deduped.append(finding.model_copy(update={"sources": merged_sources}))
                continue

            key = (
                finding.category,
                finding.evidence,
                finding.file_path,
                finding.line,
                finding.column,
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped

    # ─────────────────────────────────────────────────────────────────────────
    # semgrep integration
    # ─────────────────────────────────────────────────────────────────────────

    def _run_semgrep_findings(self, paths: Stage1Paths) -> list[Finding]:
        """Запускает semgrep на JADX-декомпилированном коде и возвращает Finding-объекты."""
        if not paths.jadx_dir.exists():
            return []
        try:
            from analysis.semgrep.runner import run_semgrep

            semgrep_out = paths.run_dir / "tools" / "semgrep"
            sg_findings = run_semgrep(
                jadx_src_dir=paths.jadx_dir,
                output_dir=semgrep_out,
                on_progress=self.on_progress,
            )
        except Exception as _exc:  # pylint: disable=broad-exception-caught
            import logging as _logging  # noqa: PLC0415
            _logging.getLogger(__name__).warning("semgrep runner failed: %s", _exc)
            if self.on_progress:
                self.on_progress(f"[semgrep] ОШИБКА: {_exc}")
            return []

        findings: list[Finding] = []
        for sgf in sg_findings:
            rel_path = sgf.file
            try:
                rel_path = str(Path(sgf.file).relative_to(paths.jadx_dir))
            except (ValueError, TypeError):
                pass
            findings.append(
                self._make_finding(
                    FindingSpec(
                        category=sgf.category,
                        evidence=sgf.message[:300] if sgf.message else sgf.rule_id,
                        file_path=rel_path,
                        line=sgf.line if sgf.line else None,
                        confidence="C2",
                        evidence_type="code",
                        tags={"semgrep"},
                        sources=[f"semgrep:{sgf.rule_id}"],
                        source=f"semgrep:{sgf.rule_id}",
                    ),
                    run_dir=paths.run_dir,
                )
            )
        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # checksec integration
    # ─────────────────────────────────────────────────────────────────────────

    def _run_checksec_findings(self, paths: Stage1Paths, so_files: list[Path]) -> list[Finding]:
        """Запускает checksec на .so файлах и возвращает Finding-объекты."""
        if not so_files:
            return []
        try:
            from analysis.checksec.runner import analyze_so_files

            checksec_out = paths.run_dir / "tools" / "checksec"
            reports = analyze_so_files(
                so_dir=paths.apktool_dir,
                output_dir=checksec_out,
                on_progress=None,
            )
        except Exception as _exc:  # pylint: disable=broad-exception-caught
            import logging as _logging  # noqa: PLC0415
            _logging.getLogger(__name__).debug("checksec runner failed: %s", _exc)
            return []

        findings: list[Finding] = []
        for r in reports:
            if r.exploitability == "low":
                continue  # только medium и high

            try:
                rel_path = str(Path(r.path).relative_to(paths.apktool_dir))
            except (ValueError, TypeError):
                rel_path = r.path

            # NX disabled
            if not r.nx:
                findings.append(
                    self._make_finding(
                        FindingSpec(
                            category="checksec_nx_disabled",
                            evidence=f"{r.name}: NX (Non-Executable stack) не включён",
                            file_path=rel_path,
                            confidence="C2",
                            evidence_type="binary",
                            tags={"checksec"},
                            sources=[f"checksec:{r.name}"],
                        ),
                        run_dir=paths.run_dir,
                    )
                )
            # Stack canary missing
            if not r.canary:
                findings.append(
                    self._make_finding(
                        FindingSpec(
                            category="checksec_no_canary",
                            evidence=f"{r.name}: стековый canary отсутствует",
                            file_path=rel_path,
                            confidence="C2",
                            evidence_type="binary",
                            tags={"checksec"},
                            sources=[f"checksec:{r.name}"],
                        ),
                        run_dir=paths.run_dir,
                    )
                )
            # PIE missing (only report for high exploitability)
            if not r.pie and r.exploitability == "high":
                findings.append(
                    self._make_finding(
                        FindingSpec(
                            category="checksec_no_pie",
                            evidence=f"{r.name}: PIE (Position Independent Executable) не включён",
                            file_path=rel_path,
                            confidence="C1",
                            evidence_type="binary",
                            tags={"checksec"},
                            sources=[f"checksec:{r.name}"],
                        ),
                        run_dir=paths.run_dir,
                    )
                )
            # RELRO missing (only report for high exploitability)
            if r.relro == "no" and r.exploitability == "high":
                findings.append(
                    self._make_finding(
                        FindingSpec(
                            category="checksec_no_relro",
                            evidence=f"{r.name}: RELRO отсутствует (GOT перезаписываем)",
                            file_path=rel_path,
                            confidence="C1",
                            evidence_type="binary",
                            tags={"checksec"},
                            sources=[f"checksec:{r.name}"],
                        ),
                        run_dir=paths.run_dir,
                    )
                )
        return findings
