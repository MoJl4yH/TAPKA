from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Stage2Config:
    avd_name: str = "tapka_api30"
    api_level: int = 30
    runtime_duration_sec: int = 180
    emulator_boot_timeout_sec: int = 180
    adb_timeout_sec: int = 30
    zeek_enabled: bool = True
    enable_https_interception: bool = False  # Enable mitmproxy HTTPS interception
    mitm_port: int = 8888                    # mitmdump listen port
    mitm_dump_path: str | None = None        # Path for .mitm flow dump file (optional)


@dataclass
class Stage2Snapshot:
    tag: str  # "before" | "after_install" | "after_runtime"
    packages_path: str = ""
    fs_tar_path: str = ""
    net_info_path: str = ""


@dataclass
class Stage2DiffResult:
    packages_diff_path: str = ""
    fs_diff_path: str = ""
    new_packages: list[str] = field(default_factory=list)
    new_paths: list[str] = field(default_factory=list)


@dataclass
class Stage2NetworkCapture:
    pcap_path: str = ""
    zeek_available: bool = False
    zeek_logs: dict[str, str] = field(default_factory=dict)
    unique_ips: int = 0
    unique_domains: int = 0
    top_hosts: list[str] = field(default_factory=list)
    tshark_tsv_files: dict[str, str] = field(default_factory=dict)  # name → path
    alerts: list[dict] = field(default_factory=list)


@dataclass
class Stage2Finding:
    """A normalized dynamic analysis finding produced by Stage2."""
    finding_id: str           # e.g. "info_firebase_fcm_usage"
    confidence: str           # "C1", "C2", "C3"
    title: str
    detail: str
    evidence: str = ""        # file path or inline evidence text
    suppressed: bool = False
    suppression_reason: str = ""
