"""Resolve Android SDK binary paths and environment at runtime."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

# Subdirectories inside ANDROID_SDK_ROOT that contain binaries
_SDK_SUBDIRS = ("emulator", "platform-tools", "build-tools")

# Standard AVD home locations (checked in order)
_AVD_HOME_CANDIDATES = (
    Path(os.path.expanduser("~")) / ".config" / ".android" / "avd",
    Path(os.path.expanduser("~")) / ".android" / "avd",
)


def _sdk_root() -> Path:
    env = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    if env:
        return Path(env)
    return Path(os.path.expanduser("~")) / "android-sdk"


def _avd_home() -> Path | None:
    """Return the directory that contains *.avd / *.ini files, or None."""
    # Prefer whatever ANDROID_AVD_HOME says
    env = os.environ.get("ANDROID_AVD_HOME")
    if env and Path(env).exists():
        return Path(env)
    for candidate in _AVD_HOME_CANDIDATES:
        if candidate.exists():
            return candidate
    return None


def find_sdk_bin(name: str) -> str:
    """Return path to an Android SDK binary.

    Search order:
    1. System PATH (e.g. /usr/bin/adb from android-sdk-build-tools apt package)
    2. $ANDROID_SDK_ROOT/<subdir>/<name>
    3. ~/android-sdk/<subdir>/<name>  (hardcoded fallback)

    Returns the name unchanged if not found — subprocess will raise FileNotFoundError.
    """
    found = shutil.which(name)
    if found:
        return found

    sdk = _sdk_root()
    for sub in _SDK_SUBDIRS:
        candidate = sdk / sub / name
        if candidate.exists():
            return str(candidate)

    # Also try the home-based path even if ANDROID_SDK_ROOT differs
    home_sdk = Path(os.path.expanduser("~")) / "android-sdk"
    if home_sdk != sdk:
        for sub in _SDK_SUBDIRS:
            candidate = home_sdk / sub / name
            if candidate.exists():
                return str(candidate)

    return name  # will surface as FileNotFoundError on subprocess call


def sdk_env() -> dict[str, str]:
    """Return an env dict with ANDROID_SDK_ROOT and ANDROID_AVD_HOME set.

    Pass this as env= to subprocess calls that need to find AVDs or SDK tools.
    The returned dict is a copy of os.environ with the Android variables added/corrected.
    """
    env = dict(os.environ)
    sdk = _sdk_root()
    env["ANDROID_SDK_ROOT"] = str(sdk)
    env["ANDROID_HOME"] = str(sdk)

    avd = _avd_home()
    if avd:
        env["ANDROID_AVD_HOME"] = str(avd)

    return env


def list_avds() -> list[str]:
    """Return names of all AVDs found on this system."""
    import subprocess  # noqa: PLC0415

    emulator_bin = find_sdk_bin("emulator")
    try:
        result = subprocess.run(
            [emulator_bin, "-list-avds"],
            capture_output=True,
            text=True,
            timeout=10,
            env=sdk_env(),
        )
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception:  # pylint: disable=broad-exception-caught
        pass

    # Fallback: scan AVD home directory directly
    avd_dir = _avd_home()
    if avd_dir:
        return [p.stem for p in avd_dir.glob("*.ini")]
    return []
