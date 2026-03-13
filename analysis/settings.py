import json
import os
from pathlib import Path

DEFAULT_WORKSPACE = "~/tapka_workspace"
SETTINGS_DIR = Path(__file__).resolve().parents[1] / ".tapka"
SETTINGS_FILE = SETTINGS_DIR / "settings.json"
_MOBSF_API_KEY_FILE = SETTINGS_DIR / ".mobsf_api_key"


def load_settings() -> dict:
    if not SETTINGS_FILE.exists():
        return {}
    try:
        return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_settings(settings: dict) -> None:
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    # Never persist api_key in settings.json
    cleaned = {k: v for k, v in settings.items() if k != "api_key"}
    if "mobsf" in cleaned and isinstance(cleaned["mobsf"], dict):
        cleaned["mobsf"] = {k: v for k, v in cleaned["mobsf"].items() if k != "api_key"}
    SETTINGS_FILE.write_text(json.dumps(cleaned, indent=2), encoding="utf-8")


def get_mobsf_api_key() -> str | None:
    """Read MobSF API key from secret file, falling back to legacy settings.json."""
    # Primary: dedicated secret file
    if _MOBSF_API_KEY_FILE.exists():
        try:
            key = _MOBSF_API_KEY_FILE.read_text(encoding="utf-8").strip()
            if key:
                return key
        except OSError:
            pass
    # Legacy fallback: old plaintext location in settings.json
    settings = load_settings()
    return settings.get("mobsf", {}).get("api_key") or None


def set_mobsf_api_key(key: str) -> None:
    """Store MobSF API key in a dedicated secret file with restricted permissions."""
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    _MOBSF_API_KEY_FILE.write_text(key.strip(), encoding="utf-8")
    try:
        os.chmod(_MOBSF_API_KEY_FILE, 0o600)
    except OSError:
        pass
