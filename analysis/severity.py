from __future__ import annotations

from typing import Iterable

from models.finding import Finding


class SeverityEngine:
    impact_table: dict[str, int] = {
        "ndv_remote_command": 5,
        "ndv_traffic_intercept_vpn": 5,
        "ndv_screen_capture_mediaprojection": 5,
        "ndv_accessibility_surveillance": 4,
        "ndv_mic_eavesdropping": 4,
        "ndv_camera_surveillance": 4,
        "ndv_geo_tracking_background": 4,
        "ndv_geo_tracking_foreground": 3,
        "ndv_clipboard_monitoring": 3,
        "ndv_sms_intercept": 4,
        "ndv_notification_listener": 3,
        "ndv_keylogging_like": 4,
        "ndv_overlay_abuse": 3,
        "sec_tls_trust_all": 3,
        "sec_hostname_verifier_bypass": 3,
        "sec_cleartext_traffic_allowed": 2,
        "sec_insecure_webview_bridge": 3,
        "sec_insecure_webview_file_access": 3,
        "sec_custom_ca_store_or_user_certs": 2,
        "sec_proxy_setting_modification": 2,
        "vul_exported_component_no_permission": 3,
        "vul_exported_provider_risky": 4,
        "vul_pendingintent_mutable": 3,
        "vul_deeplink_intent_injection": 3,
        "vul_fileprovider_misconfig": 3,
        "vul_backup_enabled": 2,
        "vul_debuggable_true": 5,
        "ndv_dynamic_code_loading": 5,
        "ndv_native_code_loader_suspicious": 3,
        "ndv_reflection_heavy": 2,
        "ndv_download_execute": 4,
        "secret_private_key_pem": 5,
        "secret_hardcoded_token_or_apikey": 4,
        "secret_jwt_embedded": 2,
        "secret_password_like": 3,
        "secret_endpoints_hardcoded": 2,
        "persist_boot_completed": 3,
        "persist_workmanager_periodic": 2,
        "persist_jobscheduler_periodic": 2,
        "persist_alarmmanager_repeating": 2,
        "anomaly_root_detection": 1,
        "anomaly_frida_xposed_magisk_detection": 2,
        "anomaly_emulator_detection": 1,
        "anomaly_obfuscation_heavy": 1,
        "anomaly_anti_debug": 2,
        "supplychain_signature_invalid": 5,
        "supplychain_signature_scheme_v1_only": 2,
        "supplychain_debug_certificate": 4,
        "supplychain_cert_expired": 3,
    }
    thresholds = {"high": 4.0, "medium": 2.5, "low": 1.5}
    confidence_multipliers = {"C3": 1.0, "C2": 0.8, "C1": 0.4}
    tag_boosts = {
        "persistence": 1,
        "network": 1,
        "background": 1,
        "exported": 1,
        "dynamic_code": 1,
        "mitm_enabler": 1,
    }

    @classmethod
    def apply(cls, findings: Iterable[Finding]) -> list[Finding]:
        for finding in findings:
            tags = set(finding.tags or set())
            base = cls.impact_table.get(finding.category, 1)
            for tag in tags:
                base += cls.tag_boosts.get(tag, 0)

            confidence = finding.confidence or "C1"
            multiplier = cls.confidence_multipliers.get(confidence, 0.4)
            score = base * multiplier
            finding.score = round(score, 2)
            finding.severity = cls._severity_for_score(score)

            if not finding.sources and finding.source:
                finding.sources = [finding.source]
            if not finding.evidence and finding.match:
                finding.evidence = finding.match
            if not finding.location and finding.file_path:
                location = finding.file_path
                if finding.line is not None:
                    location += f":{finding.line}"
                    if finding.column is not None:
                        location += f":{finding.column}"
                finding.location = location
            finding.tags = tags
        return list(findings)

    @classmethod
    def _severity_for_score(cls, score: float) -> str:
        if score >= cls.thresholds["high"]:
            return "high"
        if score >= cls.thresholds["medium"]:
            return "medium"
        if score >= cls.thresholds["low"]:
            return "low"
        return "info"
