from __future__ import annotations

from analysis.stages import STAGE_CROSS_TOOL, STAGE_DYNAMIC, STAGE_OVERALL, STAGE_STATIC


STATUS_LABELS = {
    "ok": "Успешно",
    "success": "Успешно",
    "fail": "Ошибка",
    "failed": "Ошибка",
    "partial": "Частично",
    "skipped": "Пропущено",
    "pending": "Не запускалось",
    "running": "Выполняется",
    "ready": "Готово",
    "idle": "Ожидание",
    "done": "Завершено",
    "finished": "Завершено",
    "error": "Ошибка",
    "not configured": "Не настроено",
    "missing": "Отсутствует",
    "starting...": "Запуск...",
    "starting…": "Запуск...",
    "stopping...": "Остановка...",
    "stop failed": "Ошибка остановки",
    "not run": "Не запускалось",
    "unknown": "Неизвестно",
    "not_implemented": "Не реализовано",
}

SEVERITY_LABELS = {
    "high": "Высокий",
    "medium": "Средний",
    "low": "Низкий",
    "info": "Справочно",
}

ARTIFACT_KIND_LABELS = {
    "file": "Файл",
    "dir": "Каталог",
}

STAGE_LABELS = {
    STAGE_STATIC: "Статический анализ",
    STAGE_DYNAMIC: "Динамический анализ",
    STAGE_CROSS_TOOL: "Кросс-инструментальный анализ",
    STAGE_OVERALL: "Сводный отчёт",
}

CATEGORY_LABELS = {
    "url": "URL-адреса",
    "ipv4": "IPv4-адреса",
    "sensitive_kv": "Чувствительные пары ключ-значение",
    "jwt": "JWT-токены",
    "dynamic_loading": "Динамическая загрузка",
    "anti_debug": "Противодействие отладке",
    "command_exec": "Выполнение команд",
    "root_paths": "Признаки root-доступа",
    "ndv_remote_command": "Каналы удалённого управления",
    "ndv_traffic_intercept_vpn": "Перехват трафика через VPN/TUN",
    "ndv_screen_capture_mediaprojection": "Захват экрана через MediaProjection",
    "ndv_accessibility_surveillance": "Наблюдение через Accessibility",
    "ndv_keylogging_like": "Поведение, похожее на кейлоггер",
    "ndv_mic_eavesdropping": "Скрытый доступ к микрофону",
    "ndv_camera_surveillance": "Скрытое использование камеры",
    "ndv_geo_tracking_background": "Фоновое геоотслеживание",
    "ndv_geo_tracking_foreground": "Геоотслеживание в активном режиме",
    "ndv_clipboard_monitoring": "Мониторинг буфера обмена",
    "ndv_sms_intercept": "Перехват SMS",
    "ndv_notification_listener": "Прослушивание уведомлений",
    "ndv_overlay_abuse": "Злоупотребление оверлеями",
    "sec_tls_trust_all": "Отключённая проверка TLS-сертификатов",
    "sec_hostname_verifier_bypass": "Обход проверки имени хоста",
    "sec_cleartext_traffic_allowed": "Разрешён незашифрованный трафик",
    "sec_insecure_webview_bridge": "Небезопасный bridge WebView",
    "sec_insecure_webview_file_access": "Небезопасный файловый доступ WebView",
    "sec_custom_ca_store_or_user_certs": "Нестандартное хранилище доверия CA",
    "sec_proxy_setting_modification": "Изменение настроек прокси",
    "vul_exported_component_no_permission": "Экспортируемый компонент без permission",
    "vul_exported_provider_risky": "Рискованный экспортируемый provider",
    "vul_fileprovider_misconfig": "Ошибочная конфигурация FileProvider",
    "vul_pendingintent_mutable": "Изменяемый PendingIntent",
    "vul_deeplink_intent_injection": "Инъекция данных через deeplink-intent",
    "vul_backup_enabled": "Включено резервное копирование",
    "vul_debuggable_true": "Сборка с android:debuggable=\"true\"",
    "ndv_dynamic_code_loading_dex": "Динамическая загрузка DEX-кода",
    "ndv_remote_command_shell": "Выполнение shell-команд",
    "ndv_payload_decode_load": "Декодирование и загрузка полезной нагрузки",
    "ndv_native_code_loader_suspicious": "Подозрительная загрузка нативного кода",
    "ndv_reflection_heavy": "Интенсивное использование рефлексии",
    "ndv_download_execute": "Сценарий download-and-execute",
    "secret_private_key_pem": "Встроенный приватный ключ PEM",
    "secret_hardcoded_token_or_apikey": "Жёстко заданный токен или API-ключ",
    "secret_jwt_embedded": "Встроенный JWT",
    "secret_password_like": "Строка, похожая на пароль",
    "secret_endpoints_hardcoded": "Жёстко заданные конечные точки",
    "persist_boot_completed": "Закрепление через BOOT_COMPLETED",
    "persist_workmanager_periodic": "Периодическая задача WorkManager",
    "persist_jobscheduler_periodic": "Периодическая задача JobScheduler",
    "persist_alarmmanager_repeating": "Повторяющийся AlarmManager",
    "anomaly_root_detection": "Обнаружение root",
    "anomaly_frida_xposed_magisk_detection": "Обнаружение Frida/Xposed/Magisk",
    "anomaly_emulator_detection": "Обнаружение эмулятора",
    "anomaly_obfuscation_heavy": "Сильная обфускация",
    "anomaly_anti_debug": "Противодействие отладке",
    "anomaly_anti_tamper": "Противодействие модификации APK",
    "anomaly_proxy_evasion": "Обход прокси-инспекции",
    "ndv_sms_send": "Отправка SMS",
    "ndv_device_admin": "Использование Device Admin",
    "ndv_device_identifiers": "Доступ к идентификаторам устройства",
    "ndv_contacts_access": "Доступ к контактам/журналам/календарю",
    "ndv_account_enumeration": "Перечисление учётных записей",
    "ndv_wifi_fingerprinting": "Wi‑Fi-фингерпринтинг",
    "ndv_bluetooth_enumeration": "Перечисление Bluetooth-устройств",
    "ndv_app_enumeration": "Перечисление установленных приложений",
    "ndv_proxy_bypass": "Обход прокси",
    "sec_weak_crypto": "Слабая криптография",
    "sec_predictable_random": "Предсказуемая инициализация SecureRandom",
    "sec_world_readable_writable": "Файлы world-readable/world-writable",
    "sec_external_storage_sensitive": "Чувствительные данные во внешнем хранилище",
    "sec_webview_js_eval": "Опасное исполнение JavaScript в WebView",
    "sec_sql_injection": "Признаки SQL-инъекции",
    "sec_log_sensitive_data": "Логирование чувствительных данных",
    "sec_sharedprefs_sensitive": "Чувствительные данные в SharedPreferences",
    "sec_intent_extra_no_validation": "Использование extras Intent без валидации",
    "sec_network_security_config_weak": "Слабая конфигурация networkSecurityConfig",
    "sec_certificate_pinning": "Проверка certificate pinning",
    "sec_cleartext_http_endpoint": "HTTP-конечная точка без TLS",
    "secret_hardcoded_credentials": "Жёстко заданные учётные данные",
    "sec_broadcast_receiver_no_permission": "BroadcastReceiver без ограничения permission",
    "sec_intent_extra_read": "Чтение extras из Intent",
    "sec_intent_injection_in_exported": "Инъекция Intent в экспортируемом компоненте",
    "sec_webview_js_enabled": "Включён JavaScript в WebView",
    "sec_webview_file_xss": "WebView file:// XSS",
    "sec_implicit_broadcast_send": "Отправка неявных broadcast-сообщений",
    "sec_cleartext_http_protocol": "Использование протокола HTTP",
    "sec_deprecated_http_client": "Устаревший HTTP-клиент",
    "sec_hardcoded_crypto_key": "Жёстко заданный криптографический ключ",
    "sec_static_iv": "Статический IV",
    "vul_task_hijacking": "Риск перехвата task/stack",
    "supplychain_signature_invalid": "Некорректная подпись APK",
    "supplychain_signature_scheme_v1_only": "Только схема подписи V1",
    "supplychain_debug_certificate": "Отладочный сертификат Android Debug",
    "supplychain_cert_expired": "Просроченный сертификат",
    "info_low_exerciser_coverage": "Низкое покрытие UI-экзерсайзера",
    "info_app_crashed_during_exercise": "Процесс приложения завершился во время упражнения",
    "info_app_produced_no_logcat": "Приложение не оставило сообщений в logcat",
    "info_app_no_filesystem_writes": "После выполнения нет записей в каталоге данных",
    "info_firebase_fcm_usage": "Обращение к инфраструктуре Firebase/FCM",
    "sec_runtime_cleartext_transport": "Открытый HTTP с признаками аутентификации",
    "anomaly_dns_tunneling_suspected": "Подозрение на DNS-туннелирование",
    "sec_runtime_tls_weakness": "Обнаружены слабые параметры TLS",
    "ndv_data_exfiltration_suspected": "Подозрение на эксфильтрацию данных",
    "info_beacon_detection_suppressed": "Детектирование beacon-паттерна отключено ограничением окна",
    "perm_appops_bind_accessibility_service": "Активна привязка службы Accessibility",
    "perm_appops_system_alert_window": "Используется право SYSTEM_ALERT_WINDOW",
    "perm_appops_write_settings": "Используется право WRITE_SETTINGS",
    "perm_appops_process_outgoing_calls": "Активно PROCESS_OUTGOING_CALLS",
    "ndv_suspicious_native_libs": "Загружены подозрительные нативные библиотеки",
    "backdoor_beacon_pattern": "Периодический beacon-паттерн",
    "stage2_finding": "Динамическая находка",
}


def translate_status(value: str | None) -> str:
    if value is None:
        return "-"
    text = str(value).strip()
    if not text:
        return "-"
    return STATUS_LABELS.get(text, STATUS_LABELS.get(text.lower(), text))


def translate_severity(value: str | None) -> str:
    if value is None:
        return "-"
    text = str(value).strip()
    if not text:
        return "-"
    return SEVERITY_LABELS.get(text.lower(), text)


def translate_artifact_kind(value: str | None) -> str:
    if value is None:
        return "-"
    text = str(value).strip().lower()
    return ARTIFACT_KIND_LABELS.get(text, value)


def translate_stage(value: str | None) -> str:
    if value is None:
        return "-"
    text = str(value).strip()
    return STAGE_LABELS.get(text, text)


def translate_category(value: str | None) -> str:
    if value is None:
        return "-"
    text = str(value).strip()
    if not text:
        return "-"
    return CATEGORY_LABELS.get(text, text)

