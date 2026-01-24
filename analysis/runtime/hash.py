import hashlib
from pathlib import Path


def sha256_file(path: Path) -> str:
    sha256 = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8192), b""):
            sha256.update(block)
    return sha256.hexdigest()
