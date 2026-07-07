from unittest.mock import patch

from app.scanners.dns_check import _scan_dns_sync


def _fake_resolve_factory(records: dict[tuple[str, str], list[str]]):
    def _fake_resolve(name: str, rdtype: str) -> list[str]:
        return records.get((name, rdtype), [])
    return _fake_resolve


def test_no_mx_does_not_penalize_missing_spf_dmarc():
    """
    Regresion test del bug real detectado en produccion: un dominio sin MX
    (ej. navi-site-3h8.pages.dev) NO debe recibir severity=high/weight=12-14
    por no tener SPF/DMARC, porque no envia correo.
    """
    domain = "static-site.pages.dev"
    records = {
        (domain, "A"): ["172.66.44.241"],
        (domain, "AAAA"): [],
        (domain, "MX"): [],
        (domain, "TXT"): [],
        (f"_dmarc.{domain}", "TXT"): [],
        (domain, "CAA"): [],
        (domain, "DNSKEY"): [],
    }
    with patch("app.scanners.dns_check._resolve", side_effect=_fake_resolve_factory(records)):
        findings = _scan_dns_sync(domain)

    spf = next(f for f in findings if f.check == "SPF")
    dmarc = next(f for f in findings if f.check == "DMARC")
    dkim = next(f for f in findings if f.check == "DKIM")

    assert spf.passed is True
    assert spf.weight == 0
    assert dmarc.passed is True
    assert dmarc.weight == 0
    assert dkim.passed is True
    assert dkim.weight == 0


def test_mx_present_without_spf_is_penalized():
    domain = "corp-mail.example.com"
    records = {
        (domain, "A"): ["10.0.0.1"],
        (domain, "AAAA"): [],
        (domain, "MX"): ["10 mail.example.com."],
        (domain, "TXT"): [],
        (f"_dmarc.{domain}", "TXT"): [],
        (domain, "CAA"): [],
        (domain, "DNSKEY"): [],
    }
    with patch("app.scanners.dns_check._resolve", side_effect=_fake_resolve_factory(records)):
        findings = _scan_dns_sync(domain)

    spf = next(f for f in findings if f.check == "SPF")
    dmarc = next(f for f in findings if f.check == "DMARC")

    assert spf.passed is False
    assert spf.weight == 12
    assert dmarc.passed is False
    assert dmarc.weight == 14


def test_caa_and_dnssec_checks_present():
    domain = "example.com"
    records = {
        (domain, "A"): ["93.184.216.34"],
        (domain, "AAAA"): ["2606:2800:220:1:248:1893:25c8:1946"],
        (domain, "MX"): [],
        (domain, "TXT"): [],
        (f"_dmarc.{domain}", "TXT"): [],
        (domain, "CAA"): ['0 issue "digicert.com"'],
        (domain, "DNSKEY"): ["257 3 8 AwEAA..."],
    }
    with patch("app.scanners.dns_check._resolve", side_effect=_fake_resolve_factory(records)):
        findings = _scan_dns_sync(domain)

    caa = next(f for f in findings if f.check == "CAA")
    dnssec = next(f for f in findings if f.check == "DNSSEC")

    assert caa.passed is True
    assert dnssec.passed is True
