from __future__ import annotations

import mimetypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests


DEFAULT_TIMEOUT_SEC = 30
SCAN_TIMEOUT_SEC = 300


@dataclass(frozen=True)
class MobSFResponse:
    status_code: int
    text: str
    json_data: Any | None
    headers: dict[str, str]


class MobSFClientError(RuntimeError):
    def __init__(self, message: str, response: MobSFResponse | None = None):
        super().__init__(message)
        self.response = response


class MobSFClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_sec = timeout_sec
        self.session = session or requests.Session()

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": self.api_key,
            "X-Mobsf-Api-Key": self.api_key,
        }

    def _request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        stream: bool = False,
        timeout_sec: int | None = None,
    ) -> requests.Response:
        url = f"{self.base_url}{path}"
        return self.session.request(
            method,
            url,
            headers=self._headers(),
            data=data,
            params=params,
            files=files,
            timeout=timeout_sec or self.timeout_sec,
            stream=stream,
        )

    def _parse_response(self, response: requests.Response) -> MobSFResponse:
        text = response.text
        json_data: Any | None = None
        try:
            json_data = response.json()
        except ValueError:
            json_data = None
        return MobSFResponse(
            status_code=response.status_code,
            text=text,
            json_data=json_data,
            headers=dict(response.headers),
        )

    def _post(
        self,
        path: str,
        data: dict[str, Any] | None = None,
        timeout_sec: int | None = None,
    ) -> MobSFResponse:
        response = self._request("POST", path, data=data, timeout_sec=timeout_sec)
        return self._parse_response(response)

    def _get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        timeout_sec: int | None = None,
    ) -> MobSFResponse:
        response = self._request("GET", path, params=params, timeout_sec=timeout_sec)
        return self._parse_response(response)

    def ping(self) -> MobSFResponse:
        return self._get("/")

    def upload(self, file_path: str, filename: str | None = None) -> MobSFResponse:
        with open(file_path, "rb") as handle:
            name = Path(filename or file_path).name
            content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
            response = self._request(
                "POST",
                "/api/v1/upload",
                files={"file": (name, handle, content_type)},
            )
        return self._parse_response(response)

    def scan(self, scan_hash: str, re_scan: int | None = None) -> MobSFResponse:
        data: dict[str, Any] = {"hash": scan_hash}
        if re_scan is not None:
            data["re_scan"] = str(re_scan)
        return self._post("/api/v1/scan", data=data, timeout_sec=SCAN_TIMEOUT_SEC)

    def scan_logs(self, scan_hash: str) -> MobSFResponse:
        return self._post("/api/v1/scan_logs", data={"hash": scan_hash})

    def report_json(self, scan_hash: str) -> MobSFResponse:
        return self._post("/api/v1/report_json", data={"hash": scan_hash})

    def scorecard(self, scan_hash: str) -> MobSFResponse:
        return self._post("/api/v1/scorecard", data={"hash": scan_hash})

    def download_pdf(self, scan_hash: str) -> requests.Response:
        return self._request("POST", "/api/v1/download_pdf", data={"hash": scan_hash}, stream=True)

    def view_source(self, scan_hash: str, file_path: str, source_type: str) -> MobSFResponse:
        data = {"hash": scan_hash, "file": file_path, "type": source_type}
        return self._post("/api/v1/view_source", data=data)

    def scans(self, page: int | None = None, page_size: int | None = None) -> MobSFResponse:
        params: dict[str, Any] = {}
        if page is not None:
            params["page"] = page
        if page_size is not None:
            params["page_size"] = page_size
        return self._get("/api/v1/scans", params=params or None)

    def tasks(self) -> MobSFResponse:
        return self._post("/api/v1/tasks")

    def search(self, query: str) -> MobSFResponse:
        return self._post("/api/v1/search", data={"query": query})

    def delete_scan(self, scan_hash: str) -> MobSFResponse:
        return self._post("/api/v1/delete_scan", data={"hash": scan_hash})

    def compare(self, hash1: str, hash2: str) -> MobSFResponse:
        return self._post("/api/v1/compare", data={"hash1": hash1, "hash2": hash2})

    def suppress_by_rule(self, scan_hash: str, rule_type: str, rule: str) -> MobSFResponse:
        return self._post(
            "/api/v1/suppress_by_rule",
            data={"hash": scan_hash, "type": rule_type, "rule": rule},
        )

    def suppress_by_files(self, scan_hash: str, rule_type: str, rule: str) -> MobSFResponse:
        return self._post(
            "/api/v1/suppress_by_files",
            data={"hash": scan_hash, "type": rule_type, "rule": rule},
        )

    def list_suppressions(self, scan_hash: str) -> MobSFResponse:
        return self._post("/api/v1/list_suppressions", data={"hash": scan_hash})

    def delete_suppression(self, scan_hash: str, kind: str, rule_type: str, rule: str) -> MobSFResponse:
        data = {"hash": scan_hash, "kind": kind, "type": rule_type, "rule": rule}
        return self._post("/api/v1/delete_suppression", data=data)

    def dynamic_get_apps(self) -> MobSFResponse:
        return self._get("/api/v1/dynamic/get_apps")

    def dynamic_start_analysis(
        self,
        scan_hash: str,
        re_install: int | None = None,
        install: int | None = None,
    ) -> MobSFResponse:
        data: dict[str, Any] = {"hash": scan_hash}
        if re_install is not None:
            data["re_install"] = str(re_install)
        if install is not None:
            data["install"] = str(install)
        return self._post("/api/v1/dynamic/start_analysis", data=data)

    def android_logcat(self, package: str) -> MobSFResponse:
        return self._post("/api/v1/android/logcat", data={"package": package})

    def android_mobsfy(self, identifier: str) -> MobSFResponse:
        return self._post("/api/v1/android/mobsfy", data={"identifier": identifier})

    def android_adb_command(self, cmd: str) -> MobSFResponse:
        return self._post("/api/v1/android/adb_command", data={"cmd": cmd})

    def android_root_ca(self, action: str) -> MobSFResponse:
        return self._post("/api/v1/android/root_ca", data={"action": action})

    def android_global_proxy(self, action: str) -> MobSFResponse:
        return self._post("/api/v1/android/global_proxy", data={"action": action})

    def android_activity(self, scan_hash: str, test: str) -> MobSFResponse:
        return self._post("/api/v1/android/activity", data={"hash": scan_hash, "test": test})

    def android_start_activity(self, scan_hash: str, activity: str) -> MobSFResponse:
        data = {"hash": scan_hash, "activity": activity}
        return self._post("/api/v1/android/start_activity", data=data)

    def android_tls_tests(self, scan_hash: str) -> MobSFResponse:
        return self._post("/api/v1/android/tls_tests", data={"hash": scan_hash})

    def frida_instrument(
        self,
        scan_hash: str,
        default_hooks: str,
        auxiliary_hooks: str,
        frida_code: str,
        class_name: str | None = None,
        class_search: str | None = None,
        class_trace: str | None = None,
        frida_action: str | None = None,
        new_package: str | None = None,
        pid: str | None = None,
    ) -> MobSFResponse:
        data: dict[str, Any] = {
            "hash": scan_hash,
            "default_hooks": default_hooks,
            "auxiliary_hooks": auxiliary_hooks,
            "frida_code": frida_code,
        }
        if class_name:
            data["class_name"] = class_name
        if class_search:
            data["class_search"] = class_search
        if class_trace:
            data["class_trace"] = class_trace
        if frida_action:
            data["frida_action"] = frida_action
        if new_package:
            data["new_package"] = new_package
        if pid:
            data["pid"] = pid
        return self._post("/api/v1/frida/instrument", data=data)

    def frida_api_monitor(self, scan_hash: str) -> MobSFResponse:
        return self._post("/api/v1/frida/api_monitor", data={"hash": scan_hash})

    def frida_get_dependencies(self, scan_hash: str) -> MobSFResponse:
        return self._post("/api/v1/frida/get_dependencies", data={"hash": scan_hash})

    def frida_logs(self, scan_hash: str) -> MobSFResponse:
        return self._post("/api/v1/frida/logs", data={"hash": scan_hash})

    def frida_list_scripts(self, device: str) -> MobSFResponse:
        return self._post("/api/v1/frida/list_scripts", data={"device": device})

    def frida_get_script(self, device: str, scripts: list[str]) -> MobSFResponse:
        data: list[tuple[str, str]] = [("device", device)]
        for script in scripts:
            data.append(("scripts[]", script))
        response = self._request("POST", "/api/v1/frida/get_script", data=data)
        return self._parse_response(response)

    def dynamic_stop_analysis(self, scan_hash: str) -> MobSFResponse:
        return self._post("/api/v1/dynamic/stop_analysis", data={"hash": scan_hash})

    def dynamic_report_json(self, scan_hash: str) -> MobSFResponse:
        return self._post("/api/v1/dynamic/report_json", data={"hash": scan_hash})

    def dynamic_view_source(self, scan_hash: str, file_path: str, file_type: str) -> MobSFResponse:
        data = {"hash": scan_hash, "file": file_path, "type": file_type}
        return self._post("/api/v1/dynamic/view_source", data=data)

    def ios_corellium_supported_models(self) -> MobSFResponse:
        return self._post("/api/v1/ios/corellium_supported_models")

    def ios_corellium_ios_versions(self) -> MobSFResponse:
        return self._post("/api/v1/ios/corellium_ios_versions")

    def ios_corellium_create_instance(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/corellium_create_ios_instance", data=data)

    def ios_dynamic_analysis(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/dynamic_analysis", data=data)

    def ios_corellium_start_instance(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/corellium_start_instance", data=data)

    def ios_corellium_stop_instance(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/corellium_stop_instance", data=data)

    def ios_corellium_unpause_instance(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/corellium_unpause_instance", data=data)

    def ios_corellium_reboot_instance(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/corellium_reboot_instance", data=data)

    def ios_corellium_destroy_instance(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/corellium_destroy_instance", data=data)

    def ios_corellium_list_apps(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/corellium_list_apps", data=data)

    def ios_setup_environment(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/setup_environment", data=data)

    def ios_dynamic_analyzer(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/dynamic_analyzer", data=data)

    def ios_run_app(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/run_app", data=data)

    def ios_stop_app(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/stop_app", data=data)

    def ios_remove_app(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/remove_app", data=data)

    def ios_take_screenshot(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/take_screenshot", data=data)

    def ios_get_app_container_path(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/get_app_container_path", data=data)

    def ios_network_capture(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/network_capture", data=data)

    def ios_live_pcap_download(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/live_pcap_download", data=data)

    def ios_ssh_execute(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/ssh_execute", data=data)

    def ios_download_app_data(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/download_app_data", data=data)

    def ios_instance_input(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/instance_input", data=data)

    def ios_system_logs(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/system_logs", data=data)

    def ios_file_upload(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/file_upload", data=data)

    def ios_file_download(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/ios/file_download", data=data)

    def ios_frida_instrument(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/frida/ios_instrument", data=data)

    def ios_report_json(self, **data: Any) -> MobSFResponse:
        return self._post("/api/v1/dynamic/ios_report_json", data=data)
