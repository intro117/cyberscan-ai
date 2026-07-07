"""
Motor de Security Score (0-100).

Modelo: 100 puntos base, se resta el 'weight' de cada finding que NO paso
(passed=False), acotado por severidad para evitar que un solo modulo
domine el score total. Esto es un modelo heuristico simple y transparente
(no un estandar de la industria como CVSS) - se documenta asi para no
sobre-vender precision que no existe.
"""
from __future__ import annotations

from app.models import Finding, Severity

SEVERITY_CAP = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 4,
    Severity.INFO: 2,
    Severity.OK: 0,
}


def compute_score(findings: list[Finding]) -> tuple[int, str]:
    score = 100
    for f in findings:
        if f.passed:
            continue
        deduction = min(f.weight, SEVERITY_CAP.get(f.severity, f.weight))
        score -= deduction
    score = max(0, min(100, score))
    return score, _grade(score)


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"
