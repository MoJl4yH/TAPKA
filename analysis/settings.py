import json
from pathlib import Path

DEFAULT_WORKSPACE = "~/tapka_workspace"
SETTINGS_DIR = Path(__file__).resolve().parents[1] / ".tapka"
SETTINGS_FILE = SETTINGS_DIR / "settings.json"


def load_settings() -> dict:
    if not SETTINGS_FILE.exists():
        return {}
    try:
        return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_settings(settings: dict) -> None:
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2), encoding="utf-8")
