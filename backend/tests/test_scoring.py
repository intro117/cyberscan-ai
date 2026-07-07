from app.models import Finding, Severity
from app.scoring import compute_score


def test_perfect_score_with_no_failures():
    findings = [
        Finding(module="headers", check="HSTS", severity=Severity.OK, passed=True, detail="ok", weight=12),
        Finding(module="ssl", check="Expiration", severity=Severity.OK, passed=True, detail="ok", weight=10),
    ]
    score, grade = compute_score(findings)
    assert score == 100
    assert grade == "A"


def test_critical_failure_caps_deduction():
    findings = [
        Finding(module="ssl", check="Protocol Version", severity=Severity.CRITICAL,
                passed=False, detail="TLSv1.0", weight=999),
    ]
    score, grade = compute_score(findings)
    # el weight de 999 debe quedar acotado por SEVERITY_CAP[CRITICAL] = 25
    assert score == 75
    assert grade == "B"


def test_score_never_below_zero():
    findings = [
        Finding(module="x", check=f"c{i}", severity=Severity.CRITICAL, passed=False, detail="d", weight=25)
        for i in range(10)
    ]
    score, _ = compute_score(findings)
    assert score == 0


def test_grade_boundaries():
    from app.scoring import _grade
    assert _grade(95) == "A"
    assert _grade(80) == "B"
    assert _grade(65) == "C"
    assert _grade(45) == "D"
    assert _grade(10) == "F"
