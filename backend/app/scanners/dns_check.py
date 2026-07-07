"""
Modulo: DNS, MX, SPF, DKIM, DMARC, CAA, DNSSEC
Usa dnspython para consultas reales.

CORRECCION v2 (post-analisis con dato real de navi-site-3h8.pages.dev):
SPF/DMARC/DKIM son controles anti-spoofing de EMAIL. Penalizar su ausencia en
un dominio sin registros MX (que no envia correo) es un falso positivo que
infla artificialmente la severidad del reporte. Ahora se verifica MX primero;
si no hay MX, esos 3 checks se reportan como "info, no aplica" con weight=0
en vez de "high" con weight 12-14.
"""
from __future__ import annotations

import asyncio

import dns.resolver
import dns.exception

from app.models import Finding, Severity

COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2", "mandrill"]


async def scan_dns(domain: str) -> list[Finding]:
    return await asyncio.get_event_loop().run_in_executor(None, _scan_dns_sync, domain)


def _resolve(name: str, rdtype: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    try:
        answers = resolver.resolve(name, rdtype)
        return [r.to_text().strip('"') for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout,
            dns.resolver.NoNameservers):
        return []


def _scan_dns_sync(domain: str) -> list[Finding]:
    findings: list[Finding] = []

    # --- A / AAAA ---
    a_records = _resolve(domain, "A")
    aaaa_records = _resolve(domain, "AAAA")
    if a_records:
        findings.append(Finding(
            module="dns", check="A Record", severity=Severity.OK, passed=True,
            detail=f"Registros A: {', '.join(a_records)}.", weight=3,
        ))
    else:
        findings.append(Finding(
            module="dns", check="A Record", severity=Severity.CRITICAL, passed=False,
            detail="No se encontraron registros A para el dominio.",
            remediation="Verifica la configuracion DNS del dominio.", weight=10,
        ))
    if not aaaa_records:
        findings.append(Finding(
            module="dns", check="IPv6", severity=Severity.INFO, passed=False,
            detail="No hay registros AAAA (IPv6) configurados.",
            remediation="Considera agregar soporte IPv6 (opcional, no critico).", weight=1,
        ))

    # --- MX: determina si el dominio envia/recibe correo ---
    mx_records = _resolve(domain, "MX")
    has_mail = bool(mx_records)
    findings.append(Finding(
        module="dns", check="MX Record", severity=Severity.INFO, passed=True,
        detail=f"Registros MX: {', '.join(mx_records)}." if has_mail
               else "No hay registros MX: este dominio no procesa correo entrante. "
                    "Los checks SPF/DMARC/DKIM se marcan como 'no aplica' en vez de penalizar.",
        weight=0,
    ))

    # --- SPF (solo penaliza si hay MX) ---
    txt_records = _resolve(domain, "TXT")
    spf = [t for t in txt_records if t.lower().startswith("v=spf1")]
    if not has_mail and not spf:
        findings.append(Finding(
            module="dns", check="SPF", severity=Severity.INFO, passed=True,
            detail="Sin MX y sin SPF: no aplica (el dominio no envia correo).", weight=0,
        ))
    elif spf:
        hard_fail = "-all" in spf[0]
        sev = Severity.OK if hard_fail else Severity.MEDIUM
        findings.append(Finding(
            module="dns", check="SPF", severity=sev, passed=hard_fail,
            detail=f"SPF encontrado: {spf[0]}" + ("" if hard_fail else " (no usa '-all', permite soft-fail)."),
            remediation=None if hard_fail else "Cambia el mecanismo final a '-all' para rechazar spoofing explicitamente.",
            weight=10 if hard_fail else 6,
        ))
    else:
        # Hay MX pero no hay SPF -> si aplica y si es relevante penalizar
        findings.append(Finding(
            module="dns", check="SPF", severity=Severity.HIGH, passed=False,
            detail="El dominio tiene MX (recibe correo) pero no se encontro registro SPF.",
            remediation="Publica un registro TXT SPF, ej: 'v=spf1 include:_spf.google.com -all'.",
            weight=12,
        ))

    # --- DMARC (mismo criterio) ---
    dmarc_records = _resolve(f"_dmarc.{domain}", "TXT")
    dmarc = [t for t in dmarc_records if t.lower().startswith("v=dmarc1")]
    if not has_mail and not dmarc:
        findings.append(Finding(
            module="dns", check="DMARC", severity=Severity.INFO, passed=True,
            detail="Sin MX y sin DMARC: no aplica (el dominio no envia correo). "
                   "Recomendacion opcional: publica 'v=DMARC1; p=reject;' de todas formas para "
                   "bloquear spoofing de tu dominio en emails que otros pudieran falsificar.",
            weight=0,
        ))
    elif dmarc:
        policy = "none"
        for part in dmarc[0].split(";"):
            part = part.strip()
            if part.lower().startswith("p="):
                policy = part.split("=", 1)[1].lower()
        sev = Severity.OK if policy in ("quarantine", "reject") else Severity.MEDIUM
        findings.append(Finding(
            module="dns", check="DMARC", severity=sev, passed=policy in ("quarantine", "reject"),
            detail=f"DMARC encontrado con politica p={policy}.",
            remediation=None if sev == Severity.OK else "Escala la politica DMARC a 'quarantine' o 'reject' tras validar reportes.",
            weight=12 if sev == Severity.OK else 7,
        ))
    else:
        findings.append(Finding(
            module="dns", check="DMARC", severity=Severity.HIGH, passed=False,
            detail="El dominio tiene MX (recibe correo) pero no se encontro registro DMARC.",
            remediation="Publica 'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@tudominio.com'.",
            weight=14,
        ))

    # --- DKIM (heuristico, solo relevante si hay correo) ---
    if has_mail:
        dkim_found = None
        for selector in COMMON_DKIM_SELECTORS:
            records = _resolve(f"{selector}._domainkey.{domain}", "TXT")
            if any("v=dkim1" in r.lower() for r in records):
                dkim_found = selector
                break
        if dkim_found:
            findings.append(Finding(
                module="dns", check="DKIM", severity=Severity.OK, passed=True,
                detail=f"DKIM detectado con selector '{dkim_found}'.", weight=8,
            ))
        else:
            findings.append(Finding(
                module="dns", check="DKIM", severity=Severity.INFO, passed=False,
                detail="No se detecto DKIM con selectores comunes (esto NO garantiza su ausencia; "
                       "el selector real depende del proveedor de correo).",
                remediation="Confirma el selector DKIM con tu proveedor de correo y verifica manualmente.",
                weight=4,
            ))
    else:
        findings.append(Finding(
            module="dns", check="DKIM", severity=Severity.INFO, passed=True,
            detail="Sin MX: DKIM no aplica.", weight=0,
        ))

    # --- CAA: controla que CAs pueden emitir certificados para el dominio ---
    caa_records = _resolve(domain, "CAA")
    if caa_records:
        findings.append(Finding(
            module="dns", check="CAA", severity=Severity.OK, passed=True,
            detail=f"Registro CAA presente: {'; '.join(caa_records)}.", weight=3,
        ))
    else:
        findings.append(Finding(
            module="dns", check="CAA", severity=Severity.LOW, passed=False,
            detail="No hay registro CAA: cualquier CA publica podria emitir certificados para este dominio.",
            remediation="Publica un registro CAA restringiendo las CAs autorizadas, ej: '0 issue \"letsencrypt.org\"'.",
            weight=3,
        ))

    # --- DNSSEC: verifica si la zona esta firmada (deteccion basica via DNSKEY) ---
    dnskey = _resolve(domain, "DNSKEY")
    if dnskey:
        findings.append(Finding(
            module="dns", check="DNSSEC", severity=Severity.OK, passed=True,
            detail="Se encontraron registros DNSKEY: la zona parece tener DNSSEC configurado.", weight=5,
        ))
    else:
        findings.append(Finding(
            module="dns", check="DNSSEC", severity=Severity.LOW, passed=False,
            detail="No se encontraron registros DNSKEY: la zona no parece tener DNSSEC.",
            remediation="Activa DNSSEC en tu proveedor DNS si maneja datos sensibles o transacciones (mitiga cache poisoning/spoofing).",
            weight=3,
        ))

    return findings
