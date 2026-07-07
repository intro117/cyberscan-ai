from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    OK = "ok"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    module: str
    check: str
    severity: Severity
    passed: bool
    detail: str
    remediation: Optional[str] = None
    weight: int = Field(default=5, ge=0, le=100)


class ScanRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def strip_scheme(cls, v: str) -> str:
        v = v.strip().lower()
        for prefix in ("https://", "http://"):
            if v.startswith(prefix):
                v = v[len(prefix):]
        return v.rstrip("/")


class ScanResult(BaseModel):
    domain: str
    scanned_at: datetime
    score: int = Field(ge=0, le=100)
    grade: str
    findings: list[Finding]
    modules_run: list[str]
    modules_failed: list[str] = Field(default_factory=list)
