from __future__ import annotations

import json
import math
import shutil
from pathlib import Path
from typing import Callable

from analysis.models.stage2 import Stage2NetworkCapture
from analysis.runtime.exec import run_command_capture

ZEEK_LOGS = [
    "conn.log", "dns.log", "http.log",
    "ssl.log", "files.log", "x509.log", "notice.log",
]

# Domains treated as ambient Android platform traffic — suppress from findings.
# Subdomain matching: foo.googleapis.com matches if googleapis.com is here.
_PLATFORM_SUFFIXES = frozenset({
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "android.com", "gvt1.com", "gvt2.com", "android.local",
})

# FCM/Firebase — dual-use: legitimate push OR covert C2 relay.
# Always flag at C1 with analyst note.
_FCM_DOMAINS = frozenset({
    "firebaseinstallations.googleapis.com",
    "mtalk.google.com",
    "fcm.googleapis.com",
    "push.googleapis.com",
    "fcmregistrations.googleapis.com",
})

# CDN allowlist for data-exfiltration and fastflux rules.
_CDN_SUFFIXES = frozenset({
    "google.com", "googleapis.com", "gstatic.com",
    "akamai.com", "akamaized.net", "akamaihd.net",
    "cloudflare.com", "cloudflare.net",
    "fastly.net",
    "amazonaws.com", "cloudfront.net",
    "cdn77.com",
})

# Sensitive HTTP header/URI patterns for cleartext-transport rule.
_HTTP_AUTH_HEADERS = frozenset({
    "authorization", "x-auth-token", "x-api-key",
    "cookie", "x-session-id", "x-access-token",
})
_HTTP_AUTH_URI_PATTERNS = frozenset({
    "/login", "/auth", "/token", "/password", "/signin", "/session",
})

# Obsolete TLS versions (hex as tshark reports them).
_WEAK_TLS_VERSIONS = frozenset({"0x0300", "0x0301", "0x0302"})

# Substrings that identify weak cipher suites in IANA names.
_WEAK_CIPHER_PATTERNS = ("rc4", "null", "export", "_des_", "3des", "_anon_")

# TLS 1.3 cipher suite IDs (exclusive to TLS 1.3 — used to skip false-positive weak-TLS alerts).
_TLS13_CIPHERSUITES = frozenset({"0x1301", "0x1302", "0x1303", "0x1304", "0x1305"})

# QEMU/Android emulator internal NAT subnet — traffic within this prefix is not exfiltration.
_EMULATOR_SUBNET_PREFIX = "10.0.2."


def _is_platform(host: str) -> bool:
    h = host.lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in _PLATFORM_SUFFIXES)


def _is_cdn(host: str) -> bool:
    h = host.lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in _CDN_SUFFIXES)


def _shannon_entropy(label: str) -> float:
    if not label:
        return 0.0
    freq: dict[str, int] = {}
    for c in label:
        freq[c] = freq.get(c, 0) + 1
    n = len(label)
    return -sum(f / n * math.log2(f / n) for f in freq.values())


def _read_tsv(path: Path) -> list[list[str]]:
    """Read tab-separated file, skip empty lines."""
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return [line.split("\t") for line in lines if line.strip()]
    except Exception:  # pylint: disable=broad-exception-caught
        return []


class ZeekAnalyzer:
    """Analyze a pcap file.

    Priority:
      1. Zeek  — full structured logs (conn/dns/http/ssl/files/x509)
      2. tshark — lightweight fallback, extracts IPs / DNS / HTTP hosts
                  + structured TSV exports + alert rule evaluation
      3. Neither available — saves pcap path only, zeek_available=False
    """

    def __init__(self, on_log: Callable[[str], None] | None = None) -> None:
        self._log = on_log or (lambda m: None)

    def analyze(
        self,
        pcap_path: Path,
        out_dir: Path,
        capture_duration_sec: float = 0.0,
    ) -> Stage2NetworkCapture:
        capture = Stage2NetworkCapture(pcap_path=str(pcap_path))
        out_dir.mkdir(parents=True, exist_ok=True)

        if not pcap_path.exists():
            self._log("PCAP не найден, сетевой анализ пропущен.")
            return capture

        if shutil.which("zeek"):
            self._analyze_with_zeek(pcap_path, out_dir, capture)
        elif shutil.which("tshark"):
            self._analyze_with_tshark(pcap_path, out_dir, capture, capture_duration_sec)
        else:
            self._log(
                "Zeek и tshark не установлены. "
                "PCAP сохранён для ручной проверки. "
                "Установка: sudo apt install tshark"
            )
            capture.zeek_available = False

        return capture

    # ------------------------------------------------------------------
    # Zeek backend
    # ------------------------------------------------------------------

    def _analyze_with_zeek(
        self, pcap_path: Path, out_dir: Path, capture: Stage2NetworkCapture
    ) -> None:
        self._log(f"Запуск Zeek для {pcap_path}...")
        zeek_bin = shutil.which("zeek")
        code, _, stderr = run_command_capture(
            [zeek_bin, "-r", str(pcap_path)],  # type: ignore[list-item]
            cwd=out_dir,
            timeout=120,
        )
        if code != 0:
            self._log(f"Zeek завершился с кодом {code}: {stderr.strip()[:200]}")

        capture.zeek_available = True

        for log_name in ZEEK_LOGS:
            log_path = out_dir / log_name
            if log_path.exists():
                capture.zeek_logs[log_name] = str(log_path)

        # IPs from conn.log (tab-separated; id.orig_h=col2, id.resp_h=col4)
        conn_log = out_dir / "conn.log"
        if conn_log.exists():
            ips: set[str] = set()
            try:
                for line in conn_log.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith("#"):
                        continue
                    parts = line.split("\t")
                    if len(parts) >= 5:
                        ips.add(parts[2])
                        ips.add(parts[4])
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            capture.unique_ips = len(ips)

        # Domains from dns.log (query=col9)
        dns_log = out_dir / "dns.log"
        if dns_log.exists():
            domains: set[str] = set()
            hosts: list[str] = []
            try:
                for line in dns_log.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith("#"):
                        continue
                    parts = line.split("\t")
                    if len(parts) > 9:
                        query = parts[9]
                        if query and query != "-":
                            domains.add(query)
                            hosts.append(query)
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            capture.unique_domains = len(domains)
            capture.top_hosts = list(dict.fromkeys(hosts))[:10]

        self._log(
            f"Zeek завершён: {capture.unique_ips} IP, {capture.unique_domains} доменов."
        )

    # ------------------------------------------------------------------
    # tshark backend — basic counters + structured TSV exports + alerts
    # ------------------------------------------------------------------

    def _analyze_with_tshark(
        self,
        pcap_path: Path,
        out_dir: Path,
        capture: Stage2NetworkCapture,
        capture_duration_sec: float = 0.0,
    ) -> None:
        self._log(f"Запуск tshark для {pcap_path}...")
        capture.zeek_available = True  # analysis ran, just with tshark

        # --- Unique IPs (src + dst) ---
        code, out, _ = run_command_capture(
            ["tshark", "-r", str(pcap_path), "-T", "fields",
             "-e", "ip.src", "-e", "ip.dst"],
            timeout=60,
        )
        if code == 0:
            ips: set[str] = set()
            for line in out.splitlines():
                for ip in line.split("\t"):
                    ip = ip.strip()
                    if ip:
                        ips.add(ip)
            capture.unique_ips = len(ips)
            ips_path = out_dir / "tshark_ips.txt"
            ips_path.write_text("\n".join(sorted(ips)), encoding="utf-8")
            capture.zeek_logs["tshark_ips.txt"] = str(ips_path)

        # --- DNS queries (basic) ---
        code, out, _ = run_command_capture(
            ["tshark", "-r", str(pcap_path), "-Y", "dns.flags.response == 0",
             "-T", "fields", "-e", "dns.qry.name"],
            timeout=60,
        )
        if code == 0:
            domains: set[str] = set()
            hosts: list[str] = []
            for line in out.splitlines():
                q = line.strip()
                if q:
                    domains.add(q)
                    hosts.append(q)
            capture.unique_domains = len(domains)
            capture.top_hosts = list(dict.fromkeys(hosts))[:10]
            dns_path = out_dir / "tshark_dns.txt"
            dns_path.write_text("\n".join(sorted(domains)), encoding="utf-8")
            capture.zeek_logs["tshark_dns.txt"] = str(dns_path)

        # --- HTTP hosts (basic) ---
        code, out, _ = run_command_capture(
            ["tshark", "-r", str(pcap_path), "-Y", "http.request",
             "-T", "fields", "-e", "http.host"],
            timeout=60,
        )
        if code == 0:
            http_hosts = [h.strip() for h in out.splitlines() if h.strip()]
            if http_hosts:
                http_path = out_dir / "tshark_http_hosts.txt"
                http_path.write_text("\n".join(http_hosts), encoding="utf-8")
                capture.zeek_logs["tshark_http_hosts.txt"] = str(http_path)
                extra = [h for h in http_hosts if h not in capture.top_hosts]
                capture.top_hosts = (capture.top_hosts + extra)[:10]

        self._log(
            f"tshark завершён: {capture.unique_ips} IP, {capture.unique_domains} доменов, "
            f"{len(capture.top_hosts)} узлов."
        )

        # --- Structured TSV exports for alert pipeline ---
        self._export_tshark_tsvs(pcap_path, out_dir, capture)

        # --- Alert rule evaluation ---
        alerts = self._evaluate_alerts(out_dir, capture_duration_sec)
        capture.alerts = alerts
        if alerts:
            alerts_path = out_dir / "tshark_alerts.json"
            alerts_path.write_text(
                json.dumps(alerts, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            capture.zeek_logs["tshark_alerts.json"] = str(alerts_path)
            self._log(f"Предупреждения tshark: сработало правил — {len(alerts)}.")
        else:
            self._log("Предупреждения tshark: правила не сработали.")

    def _export_tshark_tsvs(
        self, pcap_path: Path, out_dir: Path, capture: Stage2NetworkCapture
    ) -> None:
        """Export structured TSV files for alert evaluation and analyst replay."""
        tshark = "tshark"

        exports = [
            (
                "tshark_flows.tsv",
                [],  # no display filter
                [
                    "frame.time_epoch", "ip.src", "tcp.srcport", "udp.srcport",
                    "ip.dst", "tcp.dstport", "udp.dstport", "ip.proto",
                    "tcp.stream", "udp.stream", "frame.len",
                ],
            ),
            (
                "tshark_dns_detailed.tsv",
                ["dns"],
                [
                    "frame.time_epoch", "dns.qry.name", "dns.qry.type",
                    "dns.flags.response", "dns.a", "dns.aaaa", "dns.cname",
                ],
            ),
            (
                "tshark_http_detailed.tsv",
                ["http.request"],
                [
                    "frame.time_epoch", "http.host", "http.request.method",
                    "http.request.uri", "http.user_agent",
                    "http.content_type", "http.authorization",
                ],
            ),
            (
                "tshark_tls_detailed.tsv",
                ["tls.handshake"],
                [
                    "frame.time_epoch", "ip.src", "ip.dst",
                    "tls.handshake.extensions_server_name",
                    "tls.handshake.type",     # 1=ClientHello, 2=ServerHello — used to filter
                    "tls.handshake.version",  # negotiated version from ServerHello
                    "tls.handshake.ciphersuite",
                ],
            ),
        ]

        for fname, display_filter, fields in exports:
            cmd = [tshark, "-r", str(pcap_path), "-T", "fields"]
            if display_filter:
                cmd += ["-Y", " && ".join(display_filter)]
            for f in fields:
                cmd += ["-e", f]
            code, out, _ = run_command_capture(cmd, timeout=90)
            if code == 0 and out.strip():
                tsv_path = out_dir / fname
                tsv_path.write_text(out, encoding="utf-8")
                capture.tshark_tsv_files[fname] = str(tsv_path)
                capture.zeek_logs[fname] = str(tsv_path)

    # ------------------------------------------------------------------
    # Alert rule evaluation (§14.2 gates applied)
    # ------------------------------------------------------------------

    def _evaluate_alerts(
        self, out_dir: Path, capture_duration_sec: float
    ) -> list[dict]:
        alerts: list[dict] = []

        dns_rows = _read_tsv(out_dir / "tshark_dns_detailed.tsv")
        http_rows = _read_tsv(out_dir / "tshark_http_detailed.tsv")
        tls_rows = _read_tsv(out_dir / "tshark_tls_detailed.tsv")
        flow_rows = _read_tsv(out_dir / "tshark_flows.tsv")

        alerts += self._rule_fcm_usage(dns_rows)
        alerts += self._rule_cleartext_transport(http_rows)
        alerts += self._rule_dns_tunneling(dns_rows)
        alerts += self._rule_tls_weakness(tls_rows)
        alerts += self._rule_data_exfiltration(flow_rows, dns_rows)
        alerts += self._rule_beacon_window_gate(capture_duration_sec)

        return alerts

    def _rule_fcm_usage(self, dns_rows: list[list[str]]) -> list[dict]:
        """info_firebase_fcm_usage — C1, dual-use analyst note."""
        found: set[str] = set()
        for row in dns_rows:
            if len(row) < 2:
                continue
            name = row[1].lower().strip()
            # col 3 = dns.flags.response: tshark outputs "True"/"False" (capitalized)
            if len(row) > 3 and row[3].strip().lower() not in ("0", "false", ""):
                continue
            if name in _FCM_DOMAINS:
                found.add(name)

        if not found:
            return []
        return [{
            "rule_id": "info_firebase_fcm_usage",
            "confidence": "C1",
            "title": "Обнаружено подключение к инфраструктуре Firebase/FCM",
            "detail": (
                f"Обнаружены DNS-запросы к FCM/Firebase: {', '.join(sorted(found))}. "
                "Firebase — инфраструктура двойного назначения: она часто встречается в легитимных приложениях "
                "и одновременно может использоваться вредоносным ПО как скрытый ретранслятор C2. "
                "Перед повышением критичности требуется проверка аналитика."
            ),
            "evidence": "tshark_dns_detailed.tsv",
            "suppression_checks": ["проверка_атрибуции_по_окружению: не выполнена (пока нет корреляции по UID)"],
            "analyst_note": "Повышайте уровень до C2 только при прямой корреляции потока FCM с UID приложения.",
        }]

    def _rule_cleartext_transport(self, http_rows: list[list[str]]) -> list[dict]:
        """sec_runtime_cleartext_transport — C2."""
        # columns: time, host, method, uri, user_agent, content_type, authorization
        hits: list[dict] = []
        _LOOPBACK = ("127.", "::1", "10.0.2.")  # emulator loopback + NAT
        for row in http_rows:
            if len(row) < 4:
                continue
            host = row[1].strip()
            uri = row[3].strip()
            auth_header = row[6].strip() if len(row) > 6 else ""

            # Suppress: loopback / linklocal
            if any(host.startswith(p) for p in _LOOPBACK):
                continue
            # Suppress: platform allowlist host
            if _is_platform(host):
                continue
            # Suppress: known connectivity check URIs
            if uri in ("/generate_204", "/ncsi.txt", "/connectcheck.html"):
                continue

            trigger_reason = ""
            if auth_header and auth_header.lower().split(":")[0].strip() in _HTTP_AUTH_HEADERS:
                trigger_reason = f"Присутствует заголовок авторизации: {auth_header[:60]}"
            elif any(pat in uri.lower() for pat in _HTTP_AUTH_URI_PATTERNS):
                trigger_reason = f"Чувствительный URI: {uri[:100]}"

            if trigger_reason:
                hits.append({"host": host, "uri": uri, "reason": trigger_reason})

        if not hits:
            return []
        return [{
            "rule_id": "sec_runtime_cleartext_transport",
            "confidence": "C2",
            "title": "Обнаружен открытый HTTP с признаками аутентификации или сессии",
            "detail": (
                f"Обнаружено {len(hits)} HTTP-запросов с индикаторами аутентификации/сессии без шифрования. "
                f"Первый пример: host={hits[0]['host']}, uri={hits[0]['uri']}. "
                f"Причина: {hits[0]['reason']}"
            ),
            "evidence": "tshark_http_detailed.tsv",
            "suppression_checks": [
                "loopback_исключён: да",
                "разрешённый_список_платформ_проверен: да",
                "URI_проверки_доступности_исключены: да",
            ],
        }]

    def _rule_dns_tunneling(self, dns_rows: list[list[str]]) -> list[dict]:
        """anomaly_dns_tunneling_suspected — C2.
        Conditions: label length > 50 AND entropy > 3.5, OR TXT ratio > 20%.
        Requires ≥ 3 matching queries.
        """
        long_entropy_hits: list[str] = []
        txt_count = 0
        non_mdns_count = 0

        for row in dns_rows:
            if len(row) < 3:
                continue
            name = row[1].strip()
            qtype = row[2].strip()  # dns.qry.type: 1=A, 16=TXT, 28=AAAA

            # Suppress mDNS records
            if name.endswith(".local") or name.endswith(".android.local"):
                continue

            # Suppress responses (tshark outputs "True"/"False" for dns.flags.response)
            if len(row) > 3 and row[3].strip().lower() not in ("0", "false", ""):
                continue

            non_mdns_count += 1

            # TXT query count
            if qtype == "16":
                txt_count += 1

            # Check longest label for entropy
            labels = name.split(".")
            longest = max(labels, key=len) if labels else ""
            if len(longest) > 50 and _shannon_entropy(longest) > 3.5:
                long_entropy_hits.append(name)

        alerts: list[dict] = []

        if len(long_entropy_hits) >= 3:
            alerts.append({
                "rule_id": "anomaly_dns_tunneling_suspected",
                "confidence": "C2",
                "title": "Подозрение на DNS-туннелирование (длинные метки с высокой энтропией)",
                "detail": (
                    f"Обнаружено {len(long_entropy_hits)} DNS-запросов с метками длиной более 50 символов "
                    f"и энтропией Шеннона >3.5 бит/символ. "
                    f"Примеры: {', '.join(long_entropy_hits[:3])}"
                ),
                "evidence": "tshark_dns_detailed.tsv",
                "suppression_checks": [
                    "mDNS_исключён: да",
                    "минимум_3_запроса_требуется: да",
                ],
            })

        if non_mdns_count > 0 and txt_count / non_mdns_count > 0.20 and txt_count >= 3:
            alerts.append({
                "rule_id": "anomaly_dns_tunneling_suspected",
                "confidence": "C2",
                "title": "Подозрение на DNS-туннелирование (высокая доля TXT-запросов)",
                "detail": (
                    f"TXT-запросы: {txt_count}/{non_mdns_count} "
                    f"({txt_count / non_mdns_count:.0%} от не-mDNS-запросов, что выше порога 20%)."
                ),
                "evidence": "tshark_dns_detailed.tsv",
                "suppression_checks": [
                    "mDNS_исключён: да",
                    "минимум_3_TXT_запроса_требуется: да",
                ],
            })

        return alerts

    def _rule_tls_weakness(self, tls_rows: list[list[str]]) -> list[dict]:
        """sec_runtime_tls_weakness — C3 (near-zero FP on API 35+).

        Only evaluates ServerHello records (handshake_type=2) because:
        - ClientHello advertises ALL supported versions/ciphers, not what was negotiated.
        - tls.handshake.version is the negotiated version; tls.record.version is always
          0x0301 in modern TLS for backwards-compatibility and is useless for detection.
        - TLS 1.3 ServerHello carries cipher suites 0x1301-0x1303; skip those.
        """
        # columns: time, ip.src, ip.dst, sni, handshake_type, tls_version, ciphersuite
        hits: list[str] = []
        for row in tls_rows:
            if len(row) < 6:
                continue
            handshake_type = row[4].strip()
            # Only check ServerHello (type=2) — the negotiated parameters
            if handshake_type != "2":
                continue
            tls_version = row[5].strip().lower()
            cipher = row[6].strip().lower() if len(row) > 6 else ""

            # Skip TLS 1.3 sessions (cipher suites are exclusive to TLS 1.3)
            cipher_ids = {c.strip() for c in cipher.split(",")}
            if cipher_ids & _TLS13_CIPHERSUITES:
                continue

            weak_ver = tls_version and tls_version in _WEAK_TLS_VERSIONS
            weak_cipher = cipher and any(p in cipher for p in _WEAK_CIPHER_PATTERNS)

            if weak_ver or weak_cipher:
                sni = row[3].strip() or row[2].strip()
                detail = f"SNI={sni}, версия={tls_version}, шифр={cipher}"
                hits.append(detail)

        if not hits:
            return []
        return [{
            "rule_id": "sec_runtime_tls_weakness",
            "confidence": "C3",
            "title": "Обнаружена устаревшая версия TLS или слабый набор шифров",
            "detail": (
                f"Обнаружено {len(hits)} TLS-рукопожатий со слабыми параметрами. "
                f"Первый пример: {hits[0]}"
            ),
            "evidence": "tshark_tls_detailed.tsv",
            "suppression_checks": ["трафик_system_uid: не отфильтрован (нет атрибуции по UID)"],
            "analyst_note": "Для Android API 35+ вероятность ложного срабатывания близка к нулю. При срабатывании доверие высокое.",
        }]

    def _rule_data_exfiltration(
        self, flow_rows: list[list[str]], dns_rows: list[list[str]]
    ) -> list[dict]:
        """ndv_data_exfiltration_suspected — C2.
        Condition: outbound bytes to single non-platform, non-CDN host > 50 KB.
        """
        # Build reverse DNS map from dns rows: IP → hostname
        # Bug 3.1 fix: tshark separates multiple IPs with commas in TSV, not spaces
        ip_to_host: dict[str, str] = {}
        for row in dns_rows:
            if len(row) < 5:
                continue
            name = row[1].strip()
            answers_raw = (
                (row[4].strip() if len(row) > 4 else "")
                + ","
                + (row[5].strip() if len(row) > 5 else "")
            )
            for ip in answers_raw.replace(",", " ").split():
                ip = ip.strip()
                if ip and ip not in ("", "-"):
                    ip_to_host[ip] = name

        # Sum OUTBOUND bytes by destination IP (Bug 3 fix: direction filter)
        # Flows TSV: time, src, tcp_src, udp_src, dst, tcp_dst, udp_dst, proto, tcp_stream, udp_stream, len
        # Only count rows where src is in the emulator subnet (traffic originating from the device).
        # Also skip rows where dst is within the emulator subnet (loopback / NAT host / DNS server).
        bytes_by_dst: dict[str, int] = {}
        for row in flow_rows:
            if len(row) < 11:
                continue
            src = row[1].strip()
            dst = row[4].strip()
            # Direction filter: only emulator-originated traffic
            if not src.startswith(_EMULATOR_SUBNET_PREFIX):
                continue
            # Exclude intra-subnet destinations (emulator NAT, DNS 10.0.2.3, host 10.0.2.2)
            if dst.startswith(_EMULATOR_SUBNET_PREFIX):
                continue
            try:
                length = int(row[10].strip())
            except (ValueError, IndexError):
                continue
            if dst:
                bytes_by_dst[dst] = bytes_by_dst.get(dst, 0) + length

        hits: list[dict] = []
        for dst_ip, total_bytes in bytes_by_dst.items():
            if total_bytes < 50 * 1024:  # 50 KB threshold
                continue
            hostname = ip_to_host.get(dst_ip, dst_ip)
            # Suppress: CDN or platform
            if _is_cdn(hostname) or _is_platform(hostname):
                continue
            hits.append({"dst_ip": dst_ip, "hostname": hostname, "bytes": total_bytes})

        if not hits:
            return []
        hits.sort(key=lambda h: h["bytes"], reverse=True)
        return [{
            "rule_id": "ndv_data_exfiltration_suspected",
            "confidence": "C2",
            "title": f"Большой исходящий объём данных на неплатформенный узел ({hits[0]['bytes'] // 1024} КБ)",
            "detail": (
                f"Обнаружено {len(hits)} неплатформенных и не-CDN узлов с исходящим объёмом более 50 КБ. "
                f"Наибольший объём: {hits[0]['hostname']} ({hits[0]['bytes'] // 1024} КБ). "
                "Примечание: атрибуция по UID приложения отсутствует, поэтому возможен системный трафик."
            ),
            "evidence": "tshark_flows.tsv",
            "suppression_checks": [
                "разрешённый_список_CDN_применён: да",
                "разрешённый_список_платформ_применён: да",
                "порог_50КБ: да",
            ],
            "analyst_note": "Проверьте атрибуцию: для подтверждения отфильтруйте соединения по UID приложения в /proc/<pid>/net/tcp.",
        }]

    def _rule_beacon_window_gate(self, capture_duration_sec: float) -> list[dict]:
        """Beacon detection requires ≥120s window. If capture is shorter, emit gate note."""
        if capture_duration_sec > 0 and capture_duration_sec < 120:
            return [{
                "rule_id": "info_beacon_detection_suppressed",
                "confidence": "C1",
                "title": f"Детектирование beacon-паттерна отключено (окно захвата {capture_duration_sec:.0f} с < минимум 120 с)",
                "detail": (
                    "Статистическое детектирование beacon-паттерна требует не менее 5 соединений со средним интервалом более 30 с, "
                    "что требует минимального окна захвата около 150 с. "
                    "Запустите расширенный профиль с более длинным захватом, чтобы включить анализ beacon-паттерна."
                ),
                "evidence": "",
                "suppression_checks": ["ограничение_окна_beacon: захват слишком короткий для статистического анализа"],
            }]
        return []
