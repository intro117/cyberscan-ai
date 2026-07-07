import pytest
import respx
import httpx

from app.scanners.headers import scan_headers


@pytest.mark.asyncio
@respx.mock
async def test_headers_all_good():
    respx.get("https://example.com").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
                "Cross-Origin-Opener-Policy": "same-origin",
            },
        )
    )
    respx.get("http://example.com").mock(
        return_value=httpx.Response(301, headers={"Location": "https://example.com/"})
    )
    findings = await scan_headers("example.com")
    failed = [f for f in findings if not f.passed]
    assert failed == [], f"No deberian existir fallas, se encontraron: {failed}"


@pytest.mark.asyncio
@respx.mock
async def test_headers_missing_everything():
    respx.get("https://insecure.example.com").mock(return_value=httpx.Response(200, headers={}))
    respx.get("http://insecure.example.com").mock(return_value=httpx.Response(200, headers={}))
    findings = await scan_headers("insecure.example.com")
    checks_failed = {f.check for f in findings if not f.passed}
    assert "HSTS" in checks_failed
    assert "CSP" in checks_failed
    assert "Clickjacking" in checks_failed
    assert "HTTP->HTTPS Redirect" in checks_failed


@pytest.mark.asyncio
@respx.mock
async def test_headers_server_leak_detected():
    respx.get("https://leaky.example.com").mock(
        return_value=httpx.Response(200, headers={"Server": "Apache/2.4.41 (Ubuntu)"})
    )
    respx.get("http://leaky.example.com").mock(side_effect=httpx.ConnectError("refused"))
    findings = await scan_headers("leaky.example.com")
    leak_finding = next(f for f in findings if f.check == "Information Disclosure")
    assert leak_finding.passed is False
    assert "Apache" in leak_finding.detail


@pytest.mark.asyncio
@respx.mock
async def test_headers_connection_error():
    respx.get("https://unreachable.example.com").mock(side_effect=httpx.ConnectError("refused"))
    findings = await scan_headers("unreachable.example.com")
    assert len(findings) == 1
    assert findings[0].severity == "critical"


@pytest.mark.asyncio
@respx.mock
async def test_cookie_missing_flags_detected():
    respx.get("https://cookies.example.com").mock(
        return_value=httpx.Response(
            200,
            headers=[("set-cookie", "sessionid=abc123; Path=/")],
        )
    )
    respx.get("http://cookies.example.com").mock(side_effect=httpx.ConnectError("refused"))
    findings = await scan_headers("cookies.example.com")
    cookie_finding = next(f for f in findings if f.check == "Cookie Security")
    assert cookie_finding.passed is False
    assert "Secure" in cookie_finding.detail


@pytest.mark.asyncio
@respx.mock
async def test_cookie_with_all_flags_passes():
    respx.get("https://secure-cookies.example.com").mock(
        return_value=httpx.Response(
            200,
            headers=[("set-cookie", "sessionid=abc123; Secure; HttpOnly; SameSite=Strict")],
        )
    )
    respx.get("http://secure-cookies.example.com").mock(side_effect=httpx.ConnectError("refused"))
    findings = await scan_headers("secure-cookies.example.com")
    cookie_finding = next(f for f in findings if f.check == "Cookie Security")
    assert cookie_finding.passed is True


@pytest.mark.asyncio
@respx.mock
async def test_http_port_closed_is_not_penalized():
    respx.get("https://noport80.example.com").mock(return_value=httpx.Response(200, headers={}))
    respx.get("http://noport80.example.com").mock(side_effect=httpx.ConnectError("refused"))
    findings = await scan_headers("noport80.example.com")
    redirect_finding = next(f for f in findings if f.check == "HTTP->HTTPS Redirect")
    assert redirect_finding.passed is True
