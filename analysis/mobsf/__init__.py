from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass
from secrets import token_hex
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from analysis.mobsf.client import MobSFClient, MobSFClientError, MobSFResponse

MOBSF_IMAGE = "opensecurity/mobile-security-framework-mobsf:latest"
MOBSF_CONTAINER_NAME = "mobsf"
DEFAULT_MOBSF_URL = "http://127.0.0.1:8000"
API_DOCS_PATH = "/api_docs"
API_KEY_RE = re.compile(r"API Key:\s*<strong><code>([a-f0-9]{64})</code>", re.IGNORECASE)
LOG_API_KEY_RE = re.compile(r"api key[:\s]+([a-f0-9]{64})", re.IGNORECASE)


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
    match = LOG_API_KEY_RE.search(logs or "")
    if not match:
        return None
    return match.group(1)


def fetch_api_key(base_url: str, timeout_sec: int = 5) -> str | None:
    html = fetch_api_docs(base_url, timeout_sec=timeout_sec)
    return extract_api_key(html)


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
    result = _run_docker(["docker", "pull", image])
    if result.returncode != 0:
        stderr = result.stderr.strip() or "docker pull failed"
        raise RuntimeError(stderr)


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


def docker_remove(container_name: str = MOBSF_CONTAINER_NAME) -> bool:
    result = _run_docker(["docker", "rm", "-f", container_name])
    if result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        message = stderr or stdout or "docker rm failed"
        if "no such container" in message.lower():
            return False
        raise RuntimeError(message)
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


def docker_run(
    base_url: str,
    api_key: str,
    image: str = MOBSF_IMAGE,
    container_name: str = MOBSF_CONTAINER_NAME,
) -> str:
    host_port = _host_port(base_url)
    result = _run_docker(
        [
            "docker",
            "run",
            "-d",
            "--name",
            container_name,
            "-p",
            f"{host_port}:8000",
            "-e",
            f"MOBSF_API_KEY={api_key}",
            image,
        ],
    )
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
        if log and attempt % 4 == 0:
            log("Waiting for MobSF to become ready...")
        time.sleep(interval_sec)
    if responded and api_key:
        if log:
            log("MobSF responded but API key was not detected; using provided key.")
        return api_key
    return None


def ensure_mobsf_ready(
    base_url: str,
    api_key: str | None = None,
    log: Callable[[str], None] | None = None,
) -> MobSFSetupResult:
    base_url = normalize_base_url(base_url)
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
                base_url, api_key=api_key, timeout_sec=180, log=log
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
                base_url, api_key=api_key, timeout_sec=180, log=log
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
            base_url, api_key=api_key, timeout_sec=180, log=log
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
    container_id = docker_run(base_url, api_key, MOBSF_IMAGE)
    if log:
        log("Waiting for MobSF to become ready...")
    if not wait_for_api_key(base_url, api_key=api_key, timeout_sec=180, log=log):
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
    "MobSFClient",
    "MobSFClientError",
    "MobSFResponse",
    "MobSFSetupResult",
    "ensure_mobsf_ready",
    "normalize_base_url",
    "stop_mobsf",
]
