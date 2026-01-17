from pydantic import BaseModel


class ApkMeta(BaseModel):
    name: str
    sha256: str
    size: int
    imported_at: str
    path: str | None = None
