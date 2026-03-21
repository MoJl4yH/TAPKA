from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from secrets import token_hex
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from analysis.mobsf.client import MobSFClient, MobSFClientError, MobSFResponse

MOBSF_UPSTREAM_IMAGE = "opensecurity/mobile-security-framework-mobsf:latest"
MOBSF_IMAGE = "tapka/mobsf:latest"   # patched image built by setup.sh
MOBSF_CONTAINER_NAME = "mobsf"
DEFAULT_MOBSF_URL = "http://127.0.0.1:8000"
_PATCHES_DIR = Path(__file__).parent / "patches"
_MOBSF_ENV_PATCH = _PATCHES_DIR / "environment.py"
_MOBSF_ENV_TARGET = (
    "/home/mobsf/Mobile-Security-Framework-MobSF"
    "/mobsf/DynamicAnalyzer/views/android/environment.py"
)
API_DOCS_PATH = "/api_docs"
API_KEY_RE = re.compile(r"API Key:\s*<strong><code>([a-f0-9]{64})</code>", re.IGNORECASE)
LOG_API_KEY_RE = re.compile(r"api key[:\s]+([a-f0-9]{64})", re.IGNORECASE)
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


@dataclass(frozen=True)
class MobSFSetupResult:
    base_url: str
    api_key: str
    container_id: str | None
    pulled: bool
    started: bool
    already_running: bool


def normalize_base_url(base_url: str) -> str:
    base_url = (base_url or "").strip()
    if not base_url:
        return DEFAULT_MOBSF_URL
    if "://" not in base_url:
        base_url = f"http://{base_url}"
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported MobSF URL scheme: {parsed.scheme!r}. Only http/https are allowed.")
    if not parsed.hostname:
        raise ValueError("MobSF URL must include a hostname.")
    return base_url.rstrip("/")


def _api_docs_url(base_url: str) -> str:
    return f"{normalize_base_url(base_url)}{API_DOCS_PATH}"


def fetch_api_docs(base_url: str, timeout_sec: int = 5) -> str:
    url = _api_docs_url(base_url)
    req = Request(url, headers={"User-Agent": "TAPKA"})
    with urlopen(req, timeout=timeout_sec) as response:
        return response.read().decode("utf-8", errors="replace")


def extract_api_key(html: str) -> str | None:
    match = API_KEY_RE.search(html or "")
    if not match:
        return None
    return match.group(1)


def extract_api_key_from_logs(logs: str) -> str | None:
    clean = _ANSI_ESCAPE_RE.sub("", logs or "")
    match = LOG_API_KEY_RE.search(clean)
    if not match:
        return None
    return match.group(1)


def generate_api_key() -> str:
    return token_hex(32)


def _run_docker(argv: list[str], timeout_sec: int | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        check=False,
    )


def docker_pull(image: str = MOBSF_IMAGE) -> None:
    # If we're asked to "pull" the patched tapka image, pull upstream first then build.
    if image == MOBSF_IMAGE:
        result = _run_docker(["docker", "pull", MOBSF_UPSTREAM_IMAGE])
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "docker pull failed")
        _build_tapka_image()
    else:
        result = _run_docker(["docker", "pull", image])
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "docker pull failed")


def _build_tapka_image() -> None:
    """Build tapka/mobsf:latest by layering TAPKA patches on top of the upstream image."""
    import shutil
    import tempfile

    if not _MOBSF_ENV_PATCH.exists():
        return  # no patch file — skip silently
    ctx = tempfile.mkdtemp()
    try:
        shutil.copy(_MOBSF_ENV_PATCH, os.path.join(ctx, "environment.py"))
        dockerfile = (
            f"FROM {MOBSF_UPSTREAM_IMAGE}\n"
            f"COPY environment.py {_MOBSF_ENV_TARGET}\n"
        )
        Path(os.path.join(ctx, "Dockerfile")).write_text(dockerfile)
        result = _run_docker(["docker", "build", "-q", "-t", MOBSF_IMAGE, ctx])
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout).strip() or "docker build failed")
    finally:
        shutil.rmtree(ctx, ignore_errors=True)


def docker_image_exists(image: str = MOBSF_IMAGE) -> bool:
    result = _run_docker(["docker", "image", "inspect", image])
    return result.returncode == 0


def docker_container_exists(container_name: str = MOBSF_CONTAINER_NAME) -> str | None:
    result = _run_docker(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"name=^{container_name}$",
            "--format",
            "{{.ID}}",
        ],
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() or "docker ps failed"
        raise RuntimeError(stderr)
    container_id = (result.stdout or "").strip()
    return container_id or None


def docker_container_running(container_name: str = MOBSF_CONTAINER_NAME) -> bool:
    result = _run_docker(["docker", "inspect", "-f", "{{.State.Running}}", container_name])
    if result.returncode != 0:
        return False
    return (result.stdout or "").strip().lower() == "true"


def docker_start(container_name: str = MOBSF_CONTAINER_NAME) -> str:
    result = _run_docker(["docker", "start", container_name])
    if result.returncode != 0:
        stderr = result.stderr.strip() or "docker start failed"
        raise RuntimeError(stderr)
    return (result.stdout or "").strip()


def docker_stop(container_name: str = MOBSF_CONTAINER_NAME) -> bool:
    result = _run_docker(["docker", "stop", container_name])
    if result.returncode != 0:
        stderr = result.stderr.strip() or "docker stop failed"
        if "no such container" in stderr.lower():
            return False
        raise RuntimeError(stderr)
    return True


def docker_logs(container_name: str = MOBSF_CONTAINER_NAME, tail: int = 200) -> str:
    result = _run_docker(["docker", "logs", "--tail", str(tail), container_name])
    if result.returncode != 0:
        stderr = result.stderr.strip() or "docker logs failed"
        raise RuntimeError(stderr)
    return (result.stdout or "").strip()


def fetch_api_key_from_logs(container_name: str = MOBSF_CONTAINER_NAME) -> str | None:
    try:
        logs = docker_logs(container_name)
    except RuntimeError:
        return None
    return extract_api_key_from_logs(logs)


def stop_mobsf(
    container_name: str = MOBSF_CONTAINER_NAME,
    log: Callable[[str], None] | None = None,
) -> bool:
    if log:
        log("Stopping MobSF container...")
    removed = docker_stop(container_name)
    if log:
        log("MobSF container stopped." if removed else "MobSF container not found.")
    return removed


def _host_port(base_url: str, default_port: int = 8000) -> int:
    parsed = urlparse(normalize_base_url(base_url))
    if parsed.port:
        return parsed.port
    return default_port


def _docker_emulator_identifier(adb_serial: str) -> str:
    """Translate a host ADB serial to the address reachable from inside a Docker container.

    emulator-5554 → host.docker.internal:5555  (ADB port = console_port + 1)
    127.0.0.1:PORT → host.docker.internal:PORT
    """
    if adb_serial.startswith("emulator-"):
        try:
            console_port = int(adb_serial.split("-", 1)[1])
            return f"host.docker.internal:{console_port + 1}"
        except (ValueError, IndexError):
            pass
    for prefix in ("127.0.0.1:", "localhost:"):
        if adb_serial.startswith(prefix):
            port = adb_serial[len(prefix):]
            return f"host.docker.internal:{port}"
    return adb_serial


def docker_run(
    base_url: str,
    api_key: str,
    image: str = MOBSF_IMAGE,
    container_name: str = MOBSF_CONTAINER_NAME,
    emulator_id: str | None = None,
) -> str:
    host_port = _host_port(base_url)
    # On Linux use --network host (MobSF needs direct ADB access to the emulator).
    # -p is incompatible with --network host on Linux.
    # Use bridge network with host-gateway on all platforms (including Linux).
    # --network host breaks host.docker.internal resolution in existing containers.
    # host-gateway resolves to the host IP as seen from within the bridge network,
    # which allows MobSF to reach the emulator ADB at host.docker.internal:5555.
    network_args = [
        "--add-host", "host.docker.internal:host-gateway",
        # Redirect www.google.com to localhost so MobSF's internet-availability check
        # fails instantly (connection refused) instead of DNS-timing-out for ~40s.
        # This reduces container startup time from ~225s to ~105s on offline machines.
        "--add-host", "www.google.com:127.0.0.1",
    ]
    port_args = ["-p", f"{host_port}:8000"]
    env_file = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write(f"MOBSF_API_KEY={api_key}\n")
            if emulator_id:
                docker_id = _docker_emulator_identifier(emulator_id)
                f.write(f"MOBSF_ANALYZER_IDENTIFIER={docker_id}\n")
            env_file = f.name
        os.chmod(env_file, 0o600)
        result = _run_docker(
            [
                "docker",
                "run",
                "-d",
                "--name",
                container_name,
                "--restart", "unless-stopped",
                *network_args,
                *port_args,
                "--env-file",
                env_file,
                image,
            ],
        )
    finally:
        if env_file:
            try:
                os.unlink(env_file)
            except OSError:
                pass
    if result.returncode != 0:
        stderr = result.stderr.strip() or "docker run failed"
        raise RuntimeError(stderr)
    container_id = (result.stdout or "").strip()
    if not container_id:
        raise RuntimeError("docker run did not return a container id")
    return container_id


def wait_for_api_key(
    base_url: str,
    api_key: str | None = None,
    timeout_sec: int = 120,
    interval_sec: float = 2.0,
    log: Callable[[str], None] | None = None,
) -> str | None:
    start = time.monotonic()
    attempt = 0
    responded = False
    reported_missing_key = False
    while time.monotonic() - start < timeout_sec:
        attempt += 1
        try:
            html = fetch_api_docs(base_url, timeout_sec=5)
            responded = True
            extracted = extract_api_key(html)
            if extracted:
                return extracted
            if api_key:
                if log:
                    log("MobSF responded without API key in /api_docs. Using provided key.")
                return api_key
            if log and not reported_missing_key:
                log("MobSF responded but API key is not visible in /api_docs yet.")
                reported_missing_key = True
        except HTTPError as exc:
            responded = True
            if api_key:
                if log:
                    log(
                        f"MobSF responded with HTTP {exc.code}; using provided API key."
                    )
                return api_key
        except (URLError, OSError):
            pass
        elapsed = int(time.monotonic() - start)
        if log and elapsed > 0 and elapsed % 30 < interval_sec:
            log(f"Waiting for MobSF to become ready... ({elapsed}s / {timeout_sec}s)")
        time.sleep(interval_sec)
    if responded and api_key:
        if log:
            log("MobSF responded but API key was not detected; using provided key.")
        return api_key
    return None


def apply_mobsf_patches(
    container_name: str = MOBSF_CONTAINER_NAME,
    log: Callable[[str], None] | None = None,
) -> None:
    """Copy TAPKA compatibility patches into the running MobSF container.

    Patches redirect /system writes (frida-server, .mobsf-f marker) to
    /data/local/tmp so dynamic analysis works without a writable /system.
    A gunicorn SIGHUP is sent to reload the Python code.
    """
    if not _MOBSF_ENV_PATCH.exists():
        return  # patch file not present — skip silently
    try:
        result = _run_docker(
            ["docker", "cp", str(_MOBSF_ENV_PATCH), f"{container_name}:{_MOBSF_ENV_TARGET}"],
        )
        if result.returncode != 0:
            if log:
                log(f"[WARN] MobSF patch deploy failed: {(result.stderr or result.stdout).strip()}")
            return
        # Send SIGHUP to PID 1 (gunicorn master) to reload workers with fresh code
        _run_docker(["docker", "exec", container_name, "/bin/sh", "-c", "kill -HUP 1"])
        if log:
            log("MobSF TAPKA compatibility patch applied.")
    except Exception as exc:  # pylint: disable=broad-exception-caught
        if log:
            log(f"[WARN] MobSF patch: {exc}")


def _is_mobsf_patched(container_name: str = MOBSF_CONTAINER_NAME) -> bool:
    """Return True if TAPKA patches are already applied to the running container."""
    result = _run_docker([
        "docker", "exec", container_name, "/bin/sh", "-c",
        f"grep -c 'TAPKA compatibility' {_MOBSF_ENV_TARGET} 2>/dev/null || echo 0",
    ])
    return result.returncode == 0 and (result.stdout or "").strip() not in ("0", "")


def ensure_mobsf_ready(
    base_url: str,
    api_key: str | None = None,
    emulator_id: str | None = None,
    log: Callable[[str], None] | None = None,
) -> MobSFSetupResult:
    base_url = normalize_base_url(base_url)

    # Pre-check: if MOBSF_ANALYZER_IDENTIFIER is missing or wrong, stop and remove
    # the container NOW — before checking API reachability — so that the normal flow
    # below recreates it with the correct env. Without this, ensure_mobsf_ready()
    # returns early ("MobSF is already running") and Frida never gets a device.
    if emulator_id:
        cid = docker_container_exists(MOBSF_CONTAINER_NAME)
        if cid:
            docker_id = _docker_emulator_identifier(emulator_id)
            env_inspect = _run_docker([
                "docker", "inspect", "-f",
                "{{range .Config.Env}}{{.}}\n{{end}}",
                MOBSF_CONTAINER_NAME,
            ])
            env_lines = env_inspect.stdout or ""
            expected = f"MOBSF_ANALYZER_IDENTIFIER={docker_id}"
            if not any(line.strip() == expected for line in env_lines.splitlines()):
                if log:
                    log(f"Removing stale MobSF container (MOBSF_ANALYZER_IDENTIFIER={docker_id} not set → recreate)...")
                docker_stop(MOBSF_CONTAINER_NAME)
                _run_docker(["docker", "rm", "-f", MOBSF_CONTAINER_NAME])

    if log:
        log(f"Checking MobSF at {base_url}...")
    try:
        html = fetch_api_docs(base_url, timeout_sec=5)
        extracted_key = extract_api_key(html)
        if extracted_key:
            if log:
                log("MobSF is already running.")
            return MobSFSetupResult(
                base_url=base_url,
                api_key=extracted_key,
                container_id=None,
                pulled=False,
                started=False,
                already_running=True,
            )
        if api_key:
            if log:
                log("MobSF responded without API key in /api_docs. Using provided key.")
            return MobSFSetupResult(
                base_url=base_url,
                api_key=api_key,
                container_id=None,
                pulled=False,
                started=False,
                already_running=True,
            )
        if log:
            log("API key not found in /api_docs response.")
    except (HTTPError, URLError, OSError) as exc:
        if log:
            log(f"MobSF not reachable: {exc}")

    container_id = docker_container_exists(MOBSF_CONTAINER_NAME)
    # If existing container uses --network host (old config), remove it so it gets recreated
    # with --add-host host.docker.internal:host-gateway (bridge mode).
    if container_id:
        net_check = _run_docker(
            ["docker", "inspect", "-f", "{{.HostConfig.NetworkMode}}", MOBSF_CONTAINER_NAME]
        )
        if (net_check.stdout or "").strip() == "host":
            if log:
                log("Removing stale MobSF container (--network host → bridge migration)...")
            _run_docker(["docker", "rm", "-f", MOBSF_CONTAINER_NAME])
            container_id = None

    # Also recreate if the container is missing required --add-host entries.
    # - host.docker.internal: needed so MobSF can reach the emulator ADB on Linux.
    # - www.google.com:127.0.0.1: makes MobSF's internet check fail instantly (not DNS-timeout),
    #   reducing container startup time from ~225s to ~105s on offline/firewalled machines.
    if container_id:
        hosts_check = _run_docker(
            ["docker", "inspect", "-f", "{{.HostConfig.ExtraHosts}}", MOBSF_CONTAINER_NAME]
        )
        extra_hosts = hosts_check.stdout or ""
        missing = [h for h in ("host.docker.internal", "www.google.com") if h not in extra_hosts]
        if missing:
            if log:
                log(f"Removing stale MobSF container (missing --add-host {', '.join(missing)} → recreate)...")
            _run_docker(["docker", "rm", "-f", MOBSF_CONTAINER_NAME])
            container_id = None

    # Recreate if MOBSF_ANALYZER_IDENTIFIER is missing or wrong.
    # Frida needs this env var inside the container to find the ADB device.
    if container_id and emulator_id:
        docker_id = _docker_emulator_identifier(emulator_id)
        env_inspect = _run_docker([
            "docker", "inspect", "-f",
            "{{range .Config.Env}}{{.}}\n{{end}}",
            MOBSF_CONTAINER_NAME,
        ])
        env_lines = env_inspect.stdout or ""
        expected = f"MOBSF_ANALYZER_IDENTIFIER={docker_id}"
        if not any(line.strip() == expected for line in env_lines.splitlines()):
            if log:
                log(f"Removing stale MobSF container (MOBSF_ANALYZER_IDENTIFIER={docker_id} not set → recreate)...")
            _run_docker(["docker", "rm", "-f", MOBSF_CONTAINER_NAME])
            container_id = None

    if container_id and not api_key:
        if log:
            log("Looking for MobSF API key in container logs...")
        api_key = fetch_api_key_from_logs(MOBSF_CONTAINER_NAME) or api_key
        if api_key and log:
            log("MobSF API key found in container logs.")
    if container_id:
        if docker_container_running(MOBSF_CONTAINER_NAME):
            if log:
                log("MobSF container is running. Waiting for readiness...")
            existing_key = wait_for_api_key(
                base_url, api_key=api_key, timeout_sec=360, log=log
            )
            if existing_key:
                return MobSFSetupResult(
                    base_url=base_url,
                    api_key=existing_key,
                    container_id=container_id,
                    pulled=False,
                    started=False,
                    already_running=True,
                )
            if log:
                log("MobSF is running but not ready. Restarting container...")
            docker_stop(MOBSF_CONTAINER_NAME)
            docker_start(MOBSF_CONTAINER_NAME)
            if log:
                log("Waiting for MobSF to become ready after restart...")
            existing_key = wait_for_api_key(
                base_url, api_key=api_key, timeout_sec=360, log=log
            )
            if not existing_key:
                raise RuntimeError(
                    "MobSF container restarted, but /api_docs is not responding yet."
                )
            return MobSFSetupResult(
                base_url=base_url,
                api_key=existing_key,
                container_id=container_id,
                pulled=False,
                started=True,
                already_running=False,
            )

        if log:
            log("Starting existing MobSF container...")
        docker_start(MOBSF_CONTAINER_NAME)
        if log:
            log("Waiting for MobSF to become ready...")
        existing_key = wait_for_api_key(
            base_url, api_key=api_key, timeout_sec=360, log=log
        )
        if not existing_key:
            raise RuntimeError("MobSF started, but /api_docs is not responding yet.")
        return MobSFSetupResult(
            base_url=base_url,
            api_key=existing_key,
            container_id=container_id,
            pulled=False,
            started=True,
            already_running=False,
        )

    if not api_key:
        api_key = generate_api_key()
        if log:
            log("Generated a new MobSF API key.")
    else:
        if log:
            log("Using saved MobSF API key.")

    pulled = False
    if docker_image_exists(MOBSF_IMAGE):
        if log:
            log("MobSF Docker image already present. Skipping pull.")
    else:
        if log:
            log("Pulling MobSF Docker image...")
        docker_pull(MOBSF_IMAGE)
        pulled = True

    if log:
        log("Starting MobSF container...")
    container_id = docker_run(base_url, api_key, MOBSF_IMAGE, emulator_id=emulator_id)
    if log:
        log("Waiting for MobSF to become ready...")
    if not wait_for_api_key(base_url, api_key=api_key, timeout_sec=360, log=log):
        raise RuntimeError("MobSF started, but /api_docs is not responding yet.")
    return MobSFSetupResult(
        base_url=base_url,
        api_key=api_key,
        container_id=container_id,
        pulled=pulled,
        started=True,
        already_running=False,
    )


__all__ = [
    "DEFAULT_MOBSF_URL",
    "MOBSF_CONTAINER_NAME",
    "MOBSF_IMAGE",
    "MOBSF_UPSTREAM_IMAGE",
    "MobSFClient",
    "MobSFClientError",
    "MobSFResponse",
    "MobSFSetupResult",
    "apply_mobsf_patches",
    "ensure_mobsf_ready",
    "normalize_base_url",
    "stop_mobsf",
]
