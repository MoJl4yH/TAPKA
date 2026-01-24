from datetime import datetime, timezone


def now_utc_iso() -> str:
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    return timestamp.replace("+00:00", "Z")
