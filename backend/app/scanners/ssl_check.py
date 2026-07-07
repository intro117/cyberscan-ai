"""
Modulo: SSL/TLS
Obtiene el certificado real via socket + ssl, valida vigencia, protocolo negociado
y presencia de cifrados debiles conocidos.
"""
from __future__ import annotations

import asyncio
import datetime
import socket
import ssl

from app.models import Finding, Severity

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


async def scan_ssl(domain: str, port: int = 443) -> list[Finding]:
    return await asyncio.get_event_loop().run_in_executor(None, _scan_ssl_sync, domain, port)


def _scan_ssl_sync(domain: str, port: int) -> list[Finding]:
    findings: list[Finding] = []
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((domain, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
    except ssl.SSLCertVerificationError as e:
        return [Finding(
            module="ssl", check="Certificate Validity", severity=Severity.CRITICAL,
            passed=False, detail=f"El certificado no es valido: {e.verify_message}.",
            remediation="Renueva el certificado con una CA de confianza (ej. Let's Encrypt) o corrige la cadena de confianza.",
            weight=20,
        )]
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        return [Finding(
            module="ssl", check="Connectivity", severity=Severity.CRITICAL,
            passed=False, detail=f"No se pudo abrir conexion TLS en el puerto {port}: {e}.",
            remediation="Verifica que el puerto 443 este expuesto y el servicio TLS activo.",
            weight=20,
        )]

    findings.append(_check_expiry(cert))
    findings.append(_check_protocol(protocol))
    findings.append(_check_cipher(cipher))

    return findings


def _check_expiry(cert: dict) -> Finding:
    not_after = cert.get("notAfter")
    if not not_after:
        return Finding(
            module="ssl", check="Expiration", severity=Severity.MEDIUM, passed=False,
            detail="No se pudo determinar la fecha de expiracion del certificado.", weight=10,
        )
    expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    days_left = (expiry - datetime.datetime.utcnow()).days

    if days_left < 0:
        return Finding(
            module="ssl", check="Expiration", severity=Severity.CRITICAL, passed=False,
            detail=f"El certificado expiro hace {abs(days_left)} dias.",
            remediation="Renueva el certificado inmediatamente.", weight=25,
        )
    if days_left < 15:
        return Finding(
            module="ssl", check="Expiration", severity=Severity.HIGH, passed=False,
            detail=f"El certificado expira en {days_left} dias.",
            remediation="Renueva el certificado antes de la expiracion; automatiza con certbot/ACME.", weight=15,
        )
    return Finding(
        module="ssl", check="Expiration", severity=Severity.OK, passed=True,
        detail=f"Certificado valido por {days_left} dias mas.", weight=10,
    )


def _check_protocol(protocol: str | None) -> Finding:
    if protocol in WEAK_PROTOCOLS:
        return Finding(
            module="ssl", check="Protocol Version", severity=Severity.CRITICAL, passed=False,
            detail=f"Protocolo negociado inseguro: {protocol}.",
            remediation="Deshabilita TLSv1.0/1.1 y SSLv3; exige TLSv1.2 o superior.", weight=20,
        )
    return Finding(
        module="ssl", check="Protocol Version", severity=Severity.OK, passed=True,
        detail=f"Protocolo negociado: {protocol}.", weight=10,
    )


def _check_cipher(cipher: tuple | None) -> Finding:
    if not cipher:
        return Finding(
            module="ssl", check="Cipher Suite", severity=Severity.INFO, passed=False,
            detail="No se pudo determinar el cipher suite.", weight=5,
        )
    name = cipher[0]
    weak_markers = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5")
    if any(marker in name for marker in weak_markers):
        return Finding(
            module="ssl", check="Cipher Suite", severity=Severity.HIGH, passed=False,
            detail=f"Cipher suite debil detectado: {name}.",
            remediation="Reconfigura el servidor para usar solo suites AEAD modernas (AES-GCM, ChaCha20-Poly1305).",
            weight=15,
        )
    return Finding(
        module="ssl", check="Cipher Suite", severity=Severity.OK, passed=True,
        detail=f"Cipher suite: {name}.", weight=5,
    )
