"""
Fase 2: endpoints independientes del escaneo de dominio.
Verificacion de correo (HIBP) y telefono (NumVerify) - APIs oficiales, no scraping.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr, field_validator

from app.scanners.email_breach import check_email_breaches
from app.scanners.phone_check import check_phone_number
from app.scoring import compute_score
from app.models import ScanResult

router = APIRouter(prefix="/api/v1/phase2", tags=["phase2"])


class EmailCheckRequest(BaseModel):
    email: EmailStr


class PhoneCheckRequest(BaseModel):
    phone: str

    @field_validator("phone")
    @classmethod
    def basic_format_check(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 7:
            raise ValueError("Numero demasiado corto para ser valido.")
        return v


@router.post("/email", response_model=ScanResult)
async def scan_email(payload: EmailCheckRequest) -> ScanResult:
    findings = await check_email_breaches(payload.email)
    score, grade = compute_score(findings)
    return ScanResult(
        domain=payload.email,  # reutiliza el campo 'domain' del modelo para el identificador consultado
        scanned_at=datetime.now(timezone.utc),
        score=score,
        grade=grade,
        findings=findings,
        modules_run=["email_breach"],
        modules_failed=[],
    )


@router.post("/phone", response_model=ScanResult)
async def scan_phone(payload: PhoneCheckRequest) -> ScanResult:
    findings = await check_phone_number(payload.phone)
    score, grade = compute_score(findings)
    return ScanResult(
        domain=payload.phone,
        scanned_at=datetime.now(timezone.utc),
        score=score,
        grade=grade,
        findings=findings,
        modules_run=["phone_check"],
        modules_failed=[],
    )
