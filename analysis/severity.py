from __future__ import annotations

from typing import Iterable

from models.finding import Finding


class SeverityEngine:
    impact_table: dict[str, int] = {
        # --- ndv_* ---
        "ndv_remote_command": 5,
        "ndv_remote_command_shell": 5,
        "ndv_dynamic_code_loading_dex": 5,
        "ndv_native_code_loader_suspicious": 3,
        "ndv_reflection_heavy": 2,
        "ndv_download_execute": 4,
        "ndv_payload_decode_load": 5,
        "ndv_traffic_intercept_vpn": 5,
        "ndv_screen_capture_mediaprojection": 5,
        "ndv_accessibility_surveillance": 4,
        "ndv_keylogging_like": 4,
        "ndv_mic_eavesdropping": 4,
        "ndv_camera_surveillance": 4,
        "ndv_geo_tracking_background": 4,
        "ndv_geo_tracking_foreground": 3,
        "ndv_clipboard_monitoring": 3,
        "ndv_sms_intercept": 4,
        "ndv_sms_send": 4,
        "ndv_notification_listener": 3,
        "ndv_overlay_abuse": 3,
        "ndv_device_admin": 4,
        "ndv_device_identifiers": 3,
        "ndv_contacts_access": 3,
        "ndv_account_enumeration": 3,
        "ndv_wifi_fingerprinting": 2,
        "ndv_bluetooth_enumeration": 2,
        "ndv_app_enumeration": 2,
        "ndv_proxy_bypass": 3,
        # --- sec_* ---
        "sec_tls_trust_all": 3,
        "sec_hostname_verifier_bypass": 3,
        "sec_cleartext_traffic_allowed": 2,
        "sec_insecure_webview_bridge": 3,
        "sec_insecure_webview_file_access": 3,
        "sec_webview_js_eval": 3,
        "sec_custom_ca_store_or_user_certs": 2,
        "sec_proxy_setting_modification": 2,
        "sec_weak_crypto": 3,
        "sec_predictable_random": 2,
        "sec_world_readable_writable": 3,
        "sec_external_storage_sensitive": 2,
        "sec_sql_injection": 3,
        "sec_log_sensitive_data": 2,
        "sec_sharedprefs_sensitive": 2,
        "sec_intent_extra_no_validation": 2,
        "sec_network_security_config_weak": 3,
        "sec_certificate_pinning": 0,
        # --- vul_* ---
        "vul_exported_component_no_permission": 3,
        "vul_exported_provider_risky": 4,
        "vul_fileprovider_misconfig": 3,
        "vul_pendingintent_mutable": 3,
        "vul_deeplink_intent_injection": 3,
        "vul_backup_enabled": 2,
        "vul_debuggable_true": 5,
        "vul_task_hijacking": 3,
        # --- secret_* ---
        "secret_private_key_pem": 5,
        "secret_hardcoded_token_or_apikey": 4,
        "secret_jwt_embedded": 2,
        "secret_password_like": 3,
        "secret_endpoints_hardcoded": 2,
        # --- persist_* ---
        "persist_boot_completed": 3,
        "persist_workmanager_periodic": 2,
        "persist_jobscheduler_periodic": 2,
        "persist_alarmmanager_repeating": 2,
        # --- anomaly_* ---
        "anomaly_root_detection": 1,
        "anomaly_frida_xposed_magisk_detection": 2,
        "anomaly_emulator_detection": 1,
        "anomaly_obfuscation_heavy": 1,
        "anomaly_anti_debug": 2,
        "anomaly_anti_tamper": 2,
        "anomaly_proxy_evasion": 2,
        # --- supplychain_* ---
        "supplychain_signature_invalid": 5,
        "supplychain_signature_scheme_v1_only": 2,
        "supplychain_debug_certificate": 4,
        "supplychain_cert_expired": 3,
    }

    thresholds = {"high": 3.5, "medium": 2.0, "low": 1.0}

    confidence_multipliers = {"C3": 1.0, "C2": 0.75, "C1": 0.5}

    tag_boosts = {
        "persistence": 0.5,
        "network": 0.5,
        "background": 0.5,
        "exported": 0.5,
        "dynamic_code": 0.5,
        "mitm_enabler": 0.5,
        "combo_confirmed": 1.0,
    }
    max_tag_boost = 2.0

    # Категории с гарантированным минимальным severity (не зависит от confidence)
    severity_floor: dict[str, str] = {
        "vul_debuggable_true": "high",
        "supplychain_signature_invalid": "high",
        "secret_private_key_pem": "high",
        "ndv_remote_command": "medium",
        "ndv_remote_command_shell": "medium",
        "ndv_dynamic_code_loading_dex": "medium",
        "ndv_payload_decode_load": "high",
        "supplychain_debug_certificate": "medium",
    }

    @classmethod
    def apply(cls, findings: Iterable[Finding]) -> list[Finding]:
        for finding in findings:
            tags = set(finding.tags or set())
            base = cls.impact_table.get(finding.category, 1)
            tag_boost = sum(cls.tag_boosts.get(tag, 0) for tag in tags)
            tag_boost = min(tag_boost, cls.max_tag_boost)
            adjusted = base + tag_boost

            confidence = finding.confidence or "C1"
            multiplier = cls.confidence_multipliers.get(confidence, 0.5)
            score = adjusted * multiplier
            finding.score = round(score, 2)
            computed_severity = cls._severity_for_score(score)

            # Применить severity floor
            floor = cls.severity_floor.get(finding.category)
            if floor and cls._severity_rank(computed_severity) < cls._severity_rank(floor):
                finding.severity = floor
            else:
                finding.severity = computed_severity

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

    @classmethod
    def _severity_rank(cls, severity: str) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3}.get(severity, 0)
