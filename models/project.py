from pydantic import BaseModel, Field

from models.apk_meta import ApkMeta


class Project(BaseModel):
    project_id: str
    created_at: str
    apk_meta: ApkMeta | None = None
    apk_versions: list[ApkMeta] = Field(default_factory=list)
    active_apk_sha256: str | None = None
