import os


def cpu_count() -> int:
    count = os.cpu_count()
    return count or 1


def quark_processes(mode: str | None, reserve: int = 1) -> int | None:
    if mode is None:
        return None
    total = cpu_count()
    if mode == "half":
        value = total // 2
    elif mode == "minus2":
        value = total - 2
    elif mode == "minus1":
        value = total - 1
    else:
        raise ValueError(f"Unsupported quark multi-process mode: {mode}")
    if value < 1:
        value = 1
    max_allowed = total - reserve
    if max_allowed < 1:
        max_allowed = 1
    half_limit = total // 2
    if half_limit < 1:
        half_limit = 1
    if max_allowed > half_limit:
        max_allowed = half_limit
    if value > max_allowed:
        value = max_allowed
    return value
