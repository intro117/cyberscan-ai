"""
Modulo Fase 2: Verificacion de correo comprometido via XposedOrNot API.

CAMBIO DE PROVEEDOR (v2): HaveIBeenPwned elimino su tier gratuito de API en
2024 - su API v3 es 100% de pago (~3.95 USD/mes), sin excepcion. Dado que el
requisito explicito del proyecto es "cero costo, sin fondos disponibles",
se reemplaza por XposedOrNot (https://xposedornot.com), un servicio de
investigacion de seguridad con API publica gratuita, sin key requerida para
consultas basicas, documentada en https://api.xposedornot.com/docs.

POR QUE NO ES SCRAPING: es una API REST documentada oficialmente, disenada
para este uso exacto - no se hace parsing de HTML ni se imita un navegador.

LIMITACION HONESTA A TENER EN CUENTA: la cobertura de brechas de XposedOrNot
es menor que la de HIBP (que tiene acuerdos directos de reporte con empresas
y es el estandar de facto de la industria). No existe una metrica publica
comparable de "% de cobertura" entre ambos servicios, asi que no se afirma
un numero especifico aqui - la diferencia real es: gratis con menor cobertura
(XposedOrNot) vs. de pago con mayor cobertura (HIBP). Si en el futuro hay
presupuesto, el modulo hibp_email_breach.py (ver mas abajo, no activo por
defecto) puede reactivarse cambiando la funcion importada en phase2.py.
"""
from __future__ import annotations

import httpx

from app.models import Finding, Severity

XPOSEDORNOT_URL = "https://api.xposedornot.com/v1/check-email/{email}"


async def check_email_breaches(email: str) -> list[Finding]:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(XPOSEDORNOT_URL.format(email=email))
    except httpx.TimeoutException:
        return [Finding(
            module="email_breach", check="XposedOrNot Lookup", severity=Severity.INFO, passed=False,
            detail="Timeout al consultar XposedOrNot. Servicio externo no disponible temporalmente.",
            weight=0,
        )]
    except httpx.ConnectError as exc:
        return [Finding(
            module="email_breach", check="XposedOrNot Lookup", severity=Severity.INFO, passed=False,
            detail=f"No se pudo conectar con XposedOrNot: {exc}",
            weight=0,
        )]

    if resp.status_code == 404:
        return [Finding(
            module="email_breach", check="Breach Exposure", severity=Severity.OK, passed=True,
            detail=f"El correo {email} no aparece en la base de datos publica de XposedOrNot. "
                   "Nota: esto NO garantiza ausencia total de exposicion - ningun servicio "
                   "gratuito tiene cobertura completa de todas las brechas conocidas.",
            weight=0,
        )]

    if resp.status_code == 429:
        return [Finding(
            module="email_breach", check="Rate Limit", severity=Severity.INFO, passed=False,
            detail="Rate limit del servicio gratuito excedido. Espera unos minutos antes de reintentar.",
            weight=0,
        )]

    if resp.status_code != 200:
        return [Finding(
            module="email_breach", check="XposedOrNot Lookup", severity=Severity.INFO, passed=False,
            detail=f"XposedOrNot respondio con status inesperado: {resp.status_code}.",
            weight=0,
        )]

    try:
        data = resp.json()
    except ValueError:
        return [Finding(
            module="email_breach", check="XposedOrNot Lookup", severity=Severity.INFO, passed=False,
            detail="Respuesta invalida del servicio (no es JSON valido).",
            weight=0,
        )]

    breaches = data.get("breaches", [])
    # La API devuelve a veces una lista de listas (agrupada por categoria) - aplanar
    flat_breaches: list[str] = []
    for item in breaches:
        if isinstance(item, list):
            flat_breaches.extend(item)
        elif isinstance(item, str):
            flat_breaches.append(item)

    breach_count = len(flat_breaches)

    if breach_count == 0:
        return [Finding(
            module="email_breach", check="Breach Exposure", severity=Severity.OK, passed=True,
            detail=f"El correo {email} no aparece en brechas conocidas por XposedOrNot.",
            weight=0,
        )]

    severity = Severity.CRITICAL if breach_count >= 5 else (
        Severity.HIGH if breach_count >= 2 else Severity.MEDIUM
    )

    return [Finding(
        module="email_breach", check="Breach Exposure", severity=severity, passed=False,
        detail=f"El correo {email} aparece en {breach_count} brecha(s) conocida(s) por XposedOrNot: "
               f"{', '.join(flat_breaches[:10])}" + (" (y mas...)" if breach_count > 10 else "") + ".",
        remediation="Cambia la contrasena de estos servicios de inmediato si aun la usas, "
                     "activa MFA donde sea posible, y considera usar un gestor de contrasenas "
                     "con contrasenas unicas por servicio.",
        weight=min(20, 5 + breach_count * 2),
    )]
