"""
Modulo: Subdominios (reconocimiento PASIVO unicamente)

Deliberadamente NO se incluye escaneo activo de puertos (Nmap) ni verificacion
de vida de subdominios de terceros no autorizados. Se usa Certificate
Transparency (crt.sh) que es informacion publica ya indexada, sin tocar
directamente la infraestructura del objetivo. Esto es legal para cualquier
dominio publico; el escaneo activo (Nmap/OpenVAS) SOLO debe ejecutarse contra
infraestructura propia y autorizada explicitamente - ver docs/LEGAL.md.
"""
from __future__ import annotations

import httpx

from app.models import Finding, Severity

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


async def scan_subdomains(domain: str) -> list[Finding]:
    url = CRTSH_URL.format(domain=domain)
    headers = {"User-Agent": "CyberScanAI/0.1 (+passive-recon; contact: security@localhost)"}

    last_error = None
    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=20.0, headers=headers) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
                break
        except (httpx.HTTPError, ValueError) as exc:
            last_error = exc
            continue
    else:
        return [Finding(
            module="subdomains", check="Certificate Transparency Lookup",
            severity=Severity.INFO, passed=False,
            detail=f"No se pudo consultar crt.sh tras 2 intentos ({last_error}). "
                   "Este es un servicio publico gratuito de disponibilidad variable, "
                   "no un hallazgo de seguridad de tu dominio.",
            weight=0,
        )]

    names: set[str] = set()
    for entry in data:
        for n in entry.get("name_value", "").split("\n"):
            n = n.strip().lower()
            if n and not n.startswith("*."):
                names.add(n)

    subdomain_count = len({n for n in names if n != domain})

    if subdomain_count == 0:
        return [Finding(
            module="subdomains", check="Exposure Count", severity=Severity.INFO,
            passed=True, detail="No se hallaron subdominios adicionales en Certificate Transparency.",
            weight=2,
        )]

    severity = Severity.INFO if subdomain_count < 20 else Severity.LOW
    return [Finding(
        module="subdomains", check="Exposure Count", severity=severity,
        passed=subdomain_count < 20,
        detail=f"Se hallaron {subdomain_count} subdominios en registros de Certificate Transparency. "
               f"Revisa manualmente cuales siguen activos y si deberian ser publicos.",
        remediation="Da de baja subdominios obsoletos (dev/staging/test) y evita certificados wildcard innecesarios.",
        weight=4,
    )]
