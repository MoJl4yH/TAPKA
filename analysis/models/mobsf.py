from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class MobSFAppSecFinding(BaseModel):
    title: str
    description: str | None = None
    section: str | None = None
    severity: str = "warning"


class MobSFInstanceInfo(BaseModel):
    base_url: str
    version: str | None = None
    started_at: str | None = None
    finished_at: str | None = None


class MobSFFeatureFlags(BaseModel):
    enable_dynamic_android: bool = False
    enable_ios: bool = False
    cleanup_scans: bool = False
    download_pdf: bool = False
    view_source: bool = False
    frida_steps: bool = False
    tls_tests: bool = False


class MobSFArtifacts(BaseModel):
    static: dict[str, str] = Field(default_factory=dict)
    dynamic_android: dict[str, str] = Field(default_factory=dict)
    ios: dict[str, str] = Field(default_factory=dict)


class MobSFStaticSummary(BaseModel):
    app_name: str | None = None
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    security_score: int | None = None
    permissions_total: int | None = None
    exported_total: int | None = None
    urls_total: int | None = None
    domains_total: int | None = None
    trackers_total: int | None = None
    trackers_detected: int | None = None
    secrets_total: int | None = None
    crypto_total: int | None = None
    permissions_top: list[str] = Field(default_factory=list)
    exported_top: list[str] = Field(default_factory=list)
    urls_top: list[str] = Field(default_factory=list)
    domains_top: list[str] = Field(default_factory=list)
    trackers_top: list[str] = Field(default_factory=list)
    manifest_summary: dict[str, int] = Field(default_factory=dict)
    code_summary: dict[str, int] = Field(default_factory=dict)
    appsec_summary: dict[str, int] = Field(default_factory=dict)
    appsec_high: list[MobSFAppSecFinding] = Field(default_factory=list)
    appsec_warning: list[MobSFAppSecFinding] = Field(default_factory=list)
    appsec_info: list[MobSFAppSecFinding] = Field(default_factory=list)
    appsec_secure: list[MobSFAppSecFinding] = Field(default_factory=list)
    appsec_hotspot: list[MobSFAppSecFinding] = Field(default_factory=list)
    scan_hash: str | None = None
    scan_type: str | None = None
    findings_total: int | None = None
    issues: dict[str, int] = Field(default_factory=dict)
    scorecard: dict[str, Any] = Field(default_factory=dict)
    top_sections: dict[str, list[str]] = Field(default_factory=dict)


class MobSFDynamicAndroidSummary(BaseModel):
    enabled: bool = False
    status: str | None = None
    logcat_lines: int | None = None
    tls_tests: dict[str, Any] = Field(default_factory=dict)
    frida: dict[str, Any] = Field(default_factory=dict)


class MobSFIosSummary(BaseModel):
    enabled: bool = False
    status: str | None = None


class MobSFReport(BaseModel):
    instance: MobSFInstanceInfo
    features: MobSFFeatureFlags
    artifacts: MobSFArtifacts = Field(default_factory=MobSFArtifacts)
    static: MobSFStaticSummary = Field(default_factory=MobSFStaticSummary)
    dynamic_android: MobSFDynamicAndroidSummary = Field(default_factory=MobSFDynamicAndroidSummary)
    ios: MobSFIosSummary = Field(default_factory=MobSFIosSummary)
