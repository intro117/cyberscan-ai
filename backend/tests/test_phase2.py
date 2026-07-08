import pytest
import respx
import httpx
from unittest.mock import patch

from app.scanners.email_breach import check_email_breaches
from app.scanners.phone_check import check_phone_number


@pytest.mark.asyncio
@respx.mock
async def test_email_no_breaches_found():
    respx.get("https://api.xposedornot.com/v1/check-email/clean@example.com").mock(
        return_value=httpx.Response(404)
    )
    findings = await check_email_breaches("clean@example.com")
    assert len(findings) == 1
    assert findings[0].passed is True
    assert findings[0].severity == "ok"


@pytest.mark.asyncio
@respx.mock
async def test_email_with_breaches_found():
    respx.get("https://api.xposedornot.com/v1/check-email/pwned@example.com").mock(
        return_value=httpx.Response(200, json={"breaches": [["Adobe", "LinkedIn"]]})
    )
    findings = await check_email_breaches("pwned@example.com")
    assert findings[0].passed is False
    assert "Adobe" in findings[0].detail
    assert "LinkedIn" in findings[0].detail
    assert findings[0].severity == "high"  # 2 breaches -> high


@pytest.mark.asyncio
@respx.mock
async def test_email_rate_limited():
    respx.get("https://api.xposedornot.com/v1/check-email/busy@example.com").mock(
        return_value=httpx.Response(429)
    )
    findings = await check_email_breaches("busy@example.com")
    assert findings[0].check == "Rate Limit"
    assert findings[0].passed is False


@pytest.mark.asyncio
@respx.mock
async def test_phone_valid_mobile_number():
    class _FakeSettings:
        numverify_api_key = "real_key_configured"
    with patch("app.scanners.phone_check.get_settings", return_value=_FakeSettings()):
        respx.get("http://apilayer.net/api/validate").mock(
            return_value=httpx.Response(200, json={
                "valid": True, "country_name": "Mexico", "carrier": "Telcel", "line_type": "mobile",
            })
        )
        findings = await check_phone_number("+525512345678")
    assert findings[0].passed is True
    risk_finding = next(f for f in findings if f.check == "Risk Heuristic")
    assert risk_finding.passed is True


@pytest.mark.asyncio
@respx.mock
async def test_phone_voip_flagged_as_risk_not_confirmed_spam():
    class _FakeSettings:
        numverify_api_key = "real_key_configured"
    with patch("app.scanners.phone_check.get_settings", return_value=_FakeSettings()):
        respx.get("http://apilayer.net/api/validate").mock(
            return_value=httpx.Response(200, json={
                "valid": True, "country_name": "United States", "carrier": "Twilio", "line_type": "voip",
            })
        )
        findings = await check_phone_number("+15551234567")
    risk_finding = next(f for f in findings if f.check == "Risk Heuristic")
    assert risk_finding.passed is False
    assert "NO es una confirmacion" in risk_finding.detail


@pytest.mark.asyncio
@respx.mock
async def test_phone_numverify_quota_exceeded_not_misreported_as_invalid():
    """
    Regresion test del bug real detectado antes de exposicion publica: cuando
    NumVerify agota la cuota gratuita, responde HTTP 200 con success:false,
    NO con 404/429. Sin este fix, se reportaria falsamente como "numero invalido".
    """
    class _FakeSettings:
        numverify_api_key = "real_key_configured"
    with patch("app.scanners.phone_check.get_settings", return_value=_FakeSettings()):
        respx.get("http://apilayer.net/api/validate").mock(
            return_value=httpx.Response(200, json={
                "success": False,
                "error": {"code": 104, "info": "Your monthly usage limit has been reached"},
            })
        )
        findings = await check_phone_number("+525512345678")
    assert findings[0].check == "NumVerify Quota/Error"
    assert "104" in findings[0].detail
    assert "cuota mensual" in findings[0].detail


@pytest.mark.asyncio
async def test_phone_no_api_key_configured():
    class _NoKeySettings:
        numverify_api_key = "REPLACE_ME_NUMVERIFY_API_KEY"
    with patch("app.scanners.phone_check.get_settings", return_value=_NoKeySettings()):
        findings = await check_phone_number("+525512345678")
    assert findings[0].check == "NumVerify Configuration"
    assert findings[0].passed is False
