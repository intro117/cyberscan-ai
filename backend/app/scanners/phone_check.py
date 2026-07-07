"""
Modulo Fase 2: Validacion de numero telefonico via NumVerify API oficial.

ACLARACION IMPORTANTE - LEER ANTES DE USAR: esto NO es un detector de "spam".
No existe una API legal/oficial que responda "este numero esta reportado como
spam" de forma confiable y global - ese dato vive dentro de apps propietarias
(Truecaller, Hiya) que no exponen API publica para ese proposito especifico,
y sus versiones web estan protegidas contra scraping automatizado.

Lo que SI se puede verificar de forma legal y estable via NumVerify
(https://numverify.com, API oficial, plan gratuito 100 req/mes):
- Si el numero tiene formato valido
- Pais y operador (carrier) de origen
- Tipo de linea (movil, fijo, VoIP)

Un numero VoIP o de un operador conocido de "numeros virtuales desechables"
es un proxy razonable (no una prueba) de mayor riesgo de spam - se reporta
como tal, con el nivel de certeza real, no como "es spam" categorico.
"""
from __future__ import annotations

import httpx

from app.config import get_settings
from app.models import Finding, Severity

NUMVERIFY_BASE_URL = "http://apilayer.net/api/validate"

# Prefijos de operadores comunmente asociados a numeros VoIP/virtuales desechables.
# Esto es una heuristica de riesgo, NO una confirmacion de spam.
VOIP_LINE_TYPES = {"voip", "premium_rate", "unknown"}


async def check_phone_number(phone: str) -> list[Finding]:
    settings = get_settings()

    if settings.numverify_api_key.startswith("REPLACE_ME"):
        return [Finding(
            module="phone_check", check="NumVerify Configuration", severity=Severity.INFO,
            passed=False,
            detail="NUMVERIFY_API_KEY no esta configurada. Este modulo requiere una API key "
                   "(plan gratuito disponible: 100 requests/mes) de https://numverify.com.",
            remediation="Configura NUMVERIFY_API_KEY en tu .env con una key de NumVerify.",
            weight=0,
        )]

    params = {
        "access_key": settings.numverify_api_key,
        "number": phone,
        "format": 1,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(NUMVERIFY_BASE_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
    except httpx.TimeoutException:
        return [Finding(
            module="phone_check", check="NumVerify Lookup", severity=Severity.INFO, passed=False,
            detail="Timeout al consultar NumVerify. Servicio externo no disponible temporalmente.",
            weight=0,
        )]
    except httpx.HTTPError as exc:
        return [Finding(
            module="phone_check", check="NumVerify Lookup", severity=Severity.INFO, passed=False,
            detail=f"Error al consultar NumVerify: {exc}",
            weight=0,
        )]

    if not data.get("valid", False):
        return [Finding(
            module="phone_check", check="Format Validity", severity=Severity.MEDIUM, passed=False,
            detail=f"El numero '{phone}' no tiene un formato valido segun NumVerify, "
                   "o no se pudo verificar.",
            remediation="Confirma el numero en formato internacional (ej. +525512345678).",
            weight=5,
        )]

    findings = [Finding(
        module="phone_check", check="Format Validity", severity=Severity.OK, passed=True,
        detail=f"Numero valido. Pais: {data.get('country_name', 'desconocido')}, "
               f"operador: {data.get('carrier', 'desconocido')}, "
               f"tipo de linea: {data.get('line_type', 'desconocido')}.",
        weight=0,
    )]

    line_type = str(data.get("line_type", "")).lower()
    if line_type in VOIP_LINE_TYPES:
        findings.append(Finding(
            module="phone_check", check="Risk Heuristic", severity=Severity.LOW, passed=False,
            detail=f"El numero es de tipo '{line_type}'. Los numeros VoIP/virtuales tienen "
                   "estadisticamente mayor asociacion con spam/fraude que las lineas moviles "
                   "tradicionales, pero esto NO es una confirmacion de que el numero sea spam.",
            remediation="Trata este dato como una señal de riesgo adicional, no como una "
                         "conclusion definitiva. Verifica por otros medios si es critico.",
            weight=3,
        ))
    else:
        findings.append(Finding(
            module="phone_check", check="Risk Heuristic", severity=Severity.OK, passed=True,
            detail=f"Tipo de linea '{line_type}' no esta asociado a los patrones heuristicos "
                   "de mayor riesgo (VoIP/premium).",
            weight=0,
        ))

    return findings
