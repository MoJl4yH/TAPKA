"""mitmproxy HTTPS interception helpers for Stage 2 dynamic analysis.

Requires:
  - mitmproxy >= 10.0.0  (provides mitmdump)
  - openssl in PATH      (for subject_hash_old computation)
  - Emulator started with -writable-system and adb root obtained

CA installation strategy (tried in order):
  1. Bind-mount system cacerts dir (API ≤ 33):
     Copy /system/etc/security/cacerts/* + our cert to /data/local/tmp/cacerts/,
     then mount --bind /data/local/tmp/cacerts /system/etc/security/cacerts.
     Works without adb remount on API 30 google_apis.

  2. Bind-mount APEX Conscrypt cacerts dir (API 34+):
     Same approach over /apex/com.android.conscrypt/cacerts/.

  3. Fallback: adb remount + adb push (legacy images).
"""
from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

MITM_CERT_DIR = Path.home() / ".mitmproxy"
MITM_PEM = MITM_CERT_DIR / "mitmproxy-ca-cert.pem"
SYSTEM_CACERTS = "/system/etc/security/cacerts"
APEX_CACERTS = "/apex/com.android.conscrypt/cacerts"


def _adb_cmd(serial: str) -> list[str]:
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    return cmd


def _run(adb: list[str], args: list[str], timeout: int = 15) -> subprocess.CompletedProcess:  # type: ignore[type-arg]
    return subprocess.run(adb + args, capture_output=True, text=True, timeout=timeout)


def install_mitm_ca_to_emulator(serial: str, on_progress=None) -> None:
    """Install mitmproxy CA into the emulator's trusted CA store.

    Tries three strategies in order:
      1. bind-mount over /system/etc/security/cacerts    (API ≤ 33, no remount needed)
      2. bind-mount over /apex/com.android.conscrypt/cacerts  (API 34+)
      3. adb remount + adb push fallback

    Raises:
        FileNotFoundError: if mitmproxy PEM cannot be generated.
        RuntimeError: if all CA installation strategies fail.
    """
    log = on_progress or (lambda m: None)

    # ── 0. Ensure cert exists ──────────────────────────────────────────────
    if not MITM_PEM.exists():
        log("mitmproxy CA not found — running mitmdump briefly to generate certificates...")
        try:
            subprocess.run(["mitmdump", "--quiet"], timeout=3, capture_output=True)
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError as exc:
            raise FileNotFoundError(
                "mitmdump not found in PATH. Install mitmproxy: pip install mitmproxy"
            ) from exc
        if not MITM_PEM.exists():
            raise FileNotFoundError(
                f"mitmproxy CA cert not found at {MITM_PEM} after mitmdump run. "
                "Run 'mitmdump' manually once to generate certificates."
            )

    # ── 1. Compute subject_hash_old ────────────────────────────────────────
    result = subprocess.run(
        ["openssl", "x509", "-subject_hash_old", "-noout", "-in", str(MITM_PEM)],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"openssl subject_hash_old failed: {result.stderr.strip() or result.stdout.strip()}"
        )
    cert_hash = result.stdout.strip()
    if not cert_hash:
        raise RuntimeError("openssl returned empty subject_hash_old")
    # BUG-SEC-08: validate cert_hash to prevent shell injection via f-string interpolation
    if not re.match(r'^[a-f0-9]{1,16}$', cert_hash):
        raise RuntimeError(f"Invalid cert_hash from openssl: {cert_hash!r}")

    log(f"mitmproxy CA hash: {cert_hash}")
    adb = _adb_cmd(serial)
    tmp_cert = f"/data/local/tmp/{cert_hash}.0"
    tmp_cacerts_dir = "/data/local/tmp/cacerts"

    # ── 2. Push cert to /data/local/tmp (always writable) ─────────────────
    push_tmp = _run(adb, ["push", str(MITM_PEM), tmp_cert], timeout=30)
    if push_tmp.returncode != 0:
        raise RuntimeError(
            f"adb push to /data/local/tmp failed: {push_tmp.stderr.strip() or push_tmp.stdout.strip()}"
        )
    _run(adb, ["shell", "chmod", "644", tmp_cert])

    # ── 3. Strategy 1: bind-mount system cacerts dir (API ≤ 33) ───────────
    sys_cacerts_ok = False
    sys_cacerts_check = _run(adb, ["shell", "test", "-d", SYSTEM_CACERTS])
    if sys_cacerts_check.returncode == 0:
        log(f"Trying bind-mount strategy over {SYSTEM_CACERTS}...")
        # Build temp dir with all existing certs + ours (two separate adb shell calls
        # to avoid compound shell string with injected cert_hash)
        _run(adb, ["shell", "mkdir", "-p", tmp_cacerts_dir], timeout=20)
        _run(adb, ["shell", "sh", "-c", f"cp {SYSTEM_CACERTS}/* {tmp_cacerts_dir}/"], timeout=20)
        _run(adb, ["shell", "cp", tmp_cert, f"{tmp_cacerts_dir}/{cert_hash}.0"])
        _run(adb, ["shell", "chmod", "644", f"{tmp_cacerts_dir}/{cert_hash}.0"])
        _run(adb, ["shell", "chmod", "755", tmp_cacerts_dir])
        # Bind-mount
        mount_r = _run(adb, ["shell", "mount", "--bind", tmp_cacerts_dir, SYSTEM_CACERTS])
        if mount_r.returncode == 0:
            log(f"mitmproxy CA bind-mounted to system store: {SYSTEM_CACERTS}/{cert_hash}.0")
            sys_cacerts_ok = True
        else:
            log(f"[WARN] system cacerts bind-mount failed: {mount_r.stderr.strip() or mount_r.stdout.strip()}")

    # ── 4. Strategy 2: bind-mount APEX Conscrypt cacerts dir (API 34+) ────
    apex_ok = False
    apex_check = _run(adb, ["shell", "test", "-d", APEX_CACERTS])
    if apex_check.returncode == 0:
        log(f"Trying bind-mount strategy over {APEX_CACERTS}...")
        apex_tmp_dir = "/data/local/tmp/apex_cacerts"
        _run(adb, ["shell", "mkdir", "-p", apex_tmp_dir], timeout=20)
        _run(adb, ["shell", "sh", "-c", f"cp {APEX_CACERTS}/* {apex_tmp_dir}/"], timeout=20)
        _run(adb, ["shell", "cp", tmp_cert, f"{apex_tmp_dir}/{cert_hash}.0"])
        _run(adb, ["shell", "chmod", "644", f"{apex_tmp_dir}/{cert_hash}.0"])
        _run(adb, ["shell", "chmod", "755", apex_tmp_dir])
        mount_r = _run(adb, ["shell", "mount", "--bind", apex_tmp_dir, APEX_CACERTS])
        if mount_r.returncode == 0:
            log(f"mitmproxy CA bind-mounted to APEX store: {APEX_CACERTS}/{cert_hash}.0")
            apex_ok = True
        else:
            log(f"[WARN] APEX cacerts bind-mount failed: {mount_r.stderr.strip() or mount_r.stdout.strip()}")
    else:
        log("APEX Conscrypt cacerts dir not present (API ≤ 33) — skipping APEX bind-mount")

    if sys_cacerts_ok or apex_ok:
        log(f"mitmproxy CA installed to emulator (cert_hash={cert_hash})")
        return

    # ── 5. Strategy 3: adb remount + adb push (fallback) ──────────────────
    log("Bind-mount strategies failed — trying adb remount fallback...")
    remote_cert = f"{SYSTEM_CACERTS}/{cert_hash}.0"

    # adb root
    r = _run(adb, ["root"], timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"adb root failed: {r.stderr.strip() or r.stdout.strip()}")
    time.sleep(1)
    _run(adb, ["wait-for-device"], timeout=30)

    remount_ok = _do_remount(adb, log)

    if remount_ok:
        time.sleep(1)
        push = _run(adb, ["push", str(MITM_PEM), remote_cert], timeout=30)
        if push.returncode == 0:
            _run(adb, ["shell", f"chmod 644 {remote_cert}"])
            log(f"mitmproxy CA installed to system store via remount: {remote_cert}")
            return
        log(f"[WARN] adb push to system store failed despite remount: {push.stderr.strip() or push.stdout.strip()}")

    raise RuntimeError(
        "CA install failed: all strategies (bind-mount, adb remount) failed"
    )


def _do_remount(adb: list[str], log) -> bool:
    """Try adb remount with disable-verity fallback. Returns True if /system is writable."""
    try:
        r = subprocess.run(adb + ["remount"], capture_output=True, text=True, timeout=30)
        out = (r.stdout + r.stderr).strip()
        log(f"adb remount output: {out or '(empty)'}")
    except subprocess.TimeoutExpired:
        log("adb remount timed out")
        return False

    if r.returncode != 0:
        # Try disable-verity + reboot
        return _disable_verity_and_remount(adb, log)

    if "reboot" in out.lower():
        log("[WARN] adb remount requires device reboot to take effect — skipping (use bind-mount strategy instead)")
        return False

    # Verify actual writeability
    wtest = subprocess.run(
        adb + ["shell", "touch /system/.tapka_write_test && rm /system/.tapka_write_test"],
        capture_output=True, text=True, timeout=10,
    )
    if wtest.returncode != 0:
        log("[WARN] adb remount returned 0 but /system is still RO")
        return _disable_verity_and_remount(adb, log)

    return True


def _disable_verity_and_remount(adb: list[str], log) -> bool:
    """Try adb disable-verity or avbctl disable-verification, reboot, remount."""
    dv = subprocess.run(adb + ["disable-verity"], capture_output=True, text=True, timeout=15)
    disable_ok = dv.returncode == 0 or "disabled" in (dv.stdout + dv.stderr).lower()

    if not disable_ok:
        avb = subprocess.run(
            adb + ["shell", "avbctl", "disable-verification"],
            capture_output=True, text=True, timeout=15,
        )
        disable_ok = avb.returncode == 0

    if not disable_ok:
        log("AVB disable unavailable — remount fallback skipped")
        return False

    log("Verity disabled, rebooting emulator...")
    subprocess.run(adb + ["reboot"], capture_output=True, timeout=10)
    subprocess.run(adb + ["wait-for-device"], capture_output=True, timeout=120)
    time.sleep(10)
    subprocess.run(adb + ["root"], capture_output=True, timeout=30)
    subprocess.run(adb + ["wait-for-device"], capture_output=True, timeout=30)
    time.sleep(2)

    try:
        r2 = subprocess.run(adb + ["remount"], capture_output=True, text=True, timeout=30)
        out2 = (r2.stdout + r2.stderr).strip()
        log(f"adb remount (after verity disable): {out2 or '(empty)'}")
        if r2.returncode != 0 or "reboot" in out2.lower():
            return False
    except subprocess.TimeoutExpired:
        log("adb remount timed out after verity disable")
        return False

    wtest = subprocess.run(
        adb + ["shell", "touch /system/.tapka_write_test && rm /system/.tapka_write_test"],
        capture_output=True, text=True, timeout=10,
    )
    return wtest.returncode == 0


def set_emulator_proxy(
    serial: str, host: str = "10.0.2.2", port: int = 8888, on_progress=None
) -> None:
    """Set HTTP proxy on emulator via adb shell settings."""
    log = on_progress or (lambda m: None)
    adb = _adb_cmd(serial)
    subprocess.run(
        adb + ["shell", "settings", "put", "global", "http_proxy", f"{host}:{port}"],
        capture_output=True, text=True, timeout=15,
    )
    log(f"Emulator proxy set to {host}:{port}")


def unset_emulator_proxy(serial: str) -> None:
    """Remove HTTP proxy setting from emulator."""
    adb = _adb_cmd(serial)
    subprocess.run(
        adb + ["shell", "settings", "delete", "global", "http_proxy"],
        capture_output=True, text=True, timeout=15,
    )


def start_mitmproxy(
    port: int = 8888,
    dump_path: Path | None = None,
    script_path: Path | None = None,
) -> subprocess.Popen:  # type: ignore[type-arg]
    """Start mitmdump in the background and return the Popen handle.

    Args:
        port: Port for mitmdump to listen on.
        dump_path: Optional path for .mitm flow dump file.
        script_path: Optional path to a mitmproxy script (-s).

    Returns:
        subprocess.Popen instance — caller is responsible for .terminate().
    """
    cmd = ["mitmdump", "--listen-port", str(port), "--quiet"]
    if dump_path is not None:
        cmd += ["-w", str(dump_path)]
    if script_path is not None:
        cmd += ["-s", str(script_path)]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
