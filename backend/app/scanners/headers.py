"""
Modulo: HTTP Security Headers
Referencia: OWASP Secure Headers Project
https://owasp.org/www-project-secure-headers/
"""
from __future__ import annotations

import httpx

from app.models import Finding, Severity

TIMEOUT = httpx.Timeout(10.0)


async def scan_headers(domain: str) -> list[Finding]:
    findings: list[Finding] = []
    url = f"https://{domain}"

    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT, follow_redirects=True, verify=True
        ) as client:
            resp = await client.get(url)
    except httpx.ConnectError:
        return [
            Finding(
                module="headers",
                check="connectivity",
                severity=Severity.CRITICAL,
                passed=False,
                detail=f"No se pudo establecer conexion HTTPS con {domain}.",
                remediation="Verifica que el sitio responda en el puerto 443 y que el certificado TLS sea valido.",
                weight=15,
            )
        ]
    except httpx.TimeoutException:
        return [
            Finding(
                module="headers",
                check="connectivity",
                severity=Severity.HIGH,
                passed=False,
                detail=f"Timeout al conectar con {domain} (>{TIMEOUT.connect}s).",
                remediation="Revisa la latencia del servidor o del CDN.",
                weight=10,
            )
        ]

    h = {k.lower(): v for k, v in resp.headers.items()}

    findings.append(_check_hsts(h))
    findings.append(_check_csp(h))
    findings.append(_check_xcto(h))
    findings.append(_check_frame_protection(h))
    findings.append(_check_referrer_policy(h))
    findings.append(_check_permissions_policy(h))
    findings.append(_check_coop_corp(h))
    findings.append(_check_server_leak(h))
    findings.append(await _check_http_redirect(domain))
    findings.append(_check_cookies(resp))

    return findings


async def _check_http_redirect(domain: str) -> Finding:
    """Verifica que la version HTTP (puerto 80) redirija a HTTPS, no sirva contenido plano."""
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
            resp = await client.get(f"http://{domain}")
    except (httpx.ConnectError, httpx.TimeoutException):
        # Puerto 80 cerrado/no responde: aceptable, no es una falla de seguridad
        return Finding(
            module="headers", check="HTTP->HTTPS Redirect", severity=Severity.OK, passed=True,
            detail="El puerto 80 (HTTP) no responde o esta cerrado; no hay superficie de downgrade.",
            weight=6,
        )
    if resp.status_code in (301, 302, 307, 308) and resp.headers.get("location", "").startswith("https://"):
        return Finding(
            module="headers", check="HTTP->HTTPS Redirect", severity=Severity.OK, passed=True,
            detail=f"HTTP redirige correctamente a HTTPS (status {resp.status_code}).", weight=6,
        )
    return Finding(
        module="headers", check="HTTP->HTTPS Redirect", severity=Severity.HIGH, passed=False,
        detail=f"El puerto 80 responde con status {resp.status_code} sin redirigir a HTTPS.",
        remediation="Configura una redireccion 301 permanente de HTTP a HTTPS en el servidor/CDN.",
        weight=10,
    )


def _check_cookies(resp: httpx.Response) -> Finding:
    set_cookie_headers = [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]
    if not set_cookie_headers:
        return Finding(
            module="headers", check="Cookie Security", severity=Severity.INFO, passed=True,
            detail="No se establecieron cookies en la respuesta inicial (nada que evaluar).", weight=0,
        )
    issues = []
    for cookie in set_cookie_headers:
        low = cookie.lower()
        missing = []
        if "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            name = cookie.split("=")[0]
            issues.append(f"{name} (falta: {', '.join(missing)})")
    if issues:
        return Finding(
            module="headers", check="Cookie Security", severity=Severity.MEDIUM, passed=False,
            detail="Cookies sin flags de seguridad completos: " + "; ".join(issues),
            remediation="Agrega los flags Secure, HttpOnly y SameSite=Strict/Lax a todas las cookies de sesion.",
            weight=8,
        )
    return Finding(
        module="headers", check="Cookie Security", severity=Severity.OK, passed=True,
        detail="Todas las cookies detectadas tienen Secure, HttpOnly y SameSite.", weight=8,
    )


def _check_hsts(h: dict) -> Finding:
    val = h.get("strict-transport-security")
    if not val:
        return Finding(
            module="headers", check="HSTS", severity=Severity.HIGH, passed=False,
            detail="No se encontro el header Strict-Transport-Security.",
            remediation="Agrega 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
            weight=12,
        )
    max_age_ok = "max-age=" in val and not val.split("max-age=")[1].split(";")[0].strip().startswith("0")
    try:
        max_age = int(val.split("max-age=")[1].split(";")[0].strip())
    except (IndexError, ValueError):
        max_age = 0
    if max_age_ok and max_age >= 31536000:
        return Finding(
            module="headers", check="HSTS", severity=Severity.OK, passed=True,
            detail=f"HSTS presente con max-age={max_age}s.", weight=12,
        )
    return Finding(
        module="headers", check="HSTS", severity=Severity.MEDIUM, passed=False,
        detail=f"HSTS presente pero max-age insuficiente ({max_age}s, recomendado >= 31536000s).",
        remediation="Incrementa max-age a al menos 1 año (31536000 segundos).",
        weight=8,
    )


def _check_csp(h: dict) -> Finding:
    val = h.get("content-security-policy")
    if not val:
        return Finding(
            module="headers", check="CSP", severity=Severity.HIGH, passed=False,
            detail="No se encontro Content-Security-Policy.",
            remediation="Define una CSP restrictiva, por ejemplo: default-src 'self'; script-src 'self'.",
            weight=15,
        )
    unsafe = "unsafe-inline" in val or "unsafe-eval" in val
    if unsafe:
        return Finding(
            module="headers", check="CSP", severity=Severity.MEDIUM, passed=False,
            detail="CSP presente pero contiene 'unsafe-inline' o 'unsafe-eval'.",
            remediation="Elimina unsafe-inline/unsafe-eval; usa nonces o hashes para scripts inline.",
            weight=8,
        )
    return Finding(
        module="headers", check="CSP", severity=Severity.OK, passed=True,
        detail="CSP presente sin directivas inseguras evidentes.", weight=15,
    )


def _check_xcto(h: dict) -> Finding:
    val = h.get("x-content-type-options", "").lower()
    if val == "nosniff":
        return Finding(
            module="headers", check="X-Content-Type-Options", severity=Severity.OK,
            passed=True, detail="nosniff presente.", weight=5,
        )
    return Finding(
        module="headers", check="X-Content-Type-Options", severity=Severity.LOW,
        passed=False, detail="Falta X-Content-Type-Options: nosniff.",
        remediation="Agrega 'X-Content-Type-Options: nosniff'.", weight=5,
    )


def _check_frame_protection(h: dict) -> Finding:
    xfo = h.get("x-frame-options", "").lower()
    csp = h.get("content-security-policy", "").lower()
    if xfo in ("deny", "sameorigin") or "frame-ancestors" in csp:
        return Finding(
            module="headers", check="Clickjacking", severity=Severity.OK,
            passed=True, detail="Proteccion contra clickjacking presente (X-Frame-Options o frame-ancestors).",
            weight=8,
        )
    return Finding(
        module="headers", check="Clickjacking", severity=Severity.MEDIUM,
        passed=False, detail="Sin proteccion contra clickjacking.",
        remediation="Agrega 'X-Frame-Options: DENY' o 'frame-ancestors' en tu CSP.", weight=8,
    )


def _check_referrer_policy(h: dict) -> Finding:
    val = h.get("referrer-policy", "").lower()
    strict = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin"}
    if val in strict:
        return Finding(
            module="headers", check="Referrer-Policy", severity=Severity.OK,
            passed=True, detail=f"Referrer-Policy configurado como '{val}'.", weight=4,
        )
    return Finding(
        module="headers", check="Referrer-Policy", severity=Severity.LOW,
        passed=False, detail=f"Referrer-Policy ausente o poco estricto ('{val or 'ninguno'}').",
        remediation="Usa 'Referrer-Policy: strict-origin-when-cross-origin'.", weight=4,
    )


def _check_permissions_policy(h: dict) -> Finding:
    val = h.get("permissions-policy")
    if val:
        return Finding(
            module="headers", check="Permissions-Policy", severity=Severity.OK,
            passed=True, detail="Permissions-Policy presente.", weight=4,
        )
    return Finding(
        module="headers", check="Permissions-Policy", severity=Severity.LOW,
        passed=False, detail="Falta Permissions-Policy.",
        remediation="Restringe APIs de navegador, ej: 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
        weight=4,
    )


def _check_coop_corp(h: dict) -> Finding:
    coop = h.get("cross-origin-opener-policy")
    if coop:
        return Finding(
            module="headers", check="COOP", severity=Severity.OK, passed=True,
            detail="Cross-Origin-Opener-Policy presente.", weight=4,
        )
    return Finding(
        module="headers", check="COOP", severity=Severity.INFO, passed=False,
        detail="Falta Cross-Origin-Opener-Policy.",
        remediation="Agrega 'Cross-Origin-Opener-Policy: same-origin'.", weight=3,
    )


def _check_server_leak(h: dict) -> Finding:
    leaks = []
    for header in ("server", "x-powered-by", "x-aspnet-version"):
        if h.get(header):
            leaks.append(f"{header}: {h[header]}")
    if leaks:
        return Finding(
            module="headers", check="Information Disclosure", severity=Severity.LOW,
            passed=False, detail="Headers que exponen tecnologia del stack: " + "; ".join(leaks),
            remediation="Elimina o enmascara los headers Server/X-Powered-By en el proxy/CDN.", weight=5,
        )
    return Finding(
        module="headers", check="Information Disclosure", severity=Severity.OK,
        passed=True, detail="No se detectaron headers que expongan el stack tecnologico.", weight=5,
    )
