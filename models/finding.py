from typing import Literal

from pydantic import BaseModel, Field

SeverityLevel = Literal["info", "low", "medium", "high"]
ConfidenceLevel = Literal["C1", "C2", "C3"]
EvidenceType = Literal["string", "code", "manifest", "signing", "binary", "resource"]


class Finding(BaseModel):
    category: str
    severity: SeverityLevel | None = None
    confidence: ConfidenceLevel | None = None
    evidence_type: EvidenceType | None = None
    tags: set[str] = Field(default_factory=set)
    score: float | None = None
    sources: list[str] = Field(default_factory=list)
    location: str | None = None
    evidence: str | None = None

    match: str | None = None
    file_path: str = ""
    line: int | None = None
    column: int | None = None
    source: str | None = None
