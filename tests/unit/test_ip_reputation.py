"""
PhisMail — IP Reputation Client Tests
"""

import asyncio
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from app.services.threat_intelligence.ip_reputation_client import (
    check_ip_reputation,
    IpReputationResult,
    HIGH_RISK_COUNTRIES,
)


def _run(coro):
    """Helper to run async tests without pytest-asyncio."""
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_mock_client(response):
    """Create a mock httpx.AsyncClient with the given response."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=response)
    return mock_client


def _make_response(status_code, data=None):
    """Create a mock httpx response."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    if data is not None:
        mock_response.json.return_value = {"data": data}
    return mock_response


class TestCheckIpReputation:
    """Test AbuseIPDB IP reputation lookups."""

    def test_returns_none_without_ip(self):
        result = _run(check_ip_reputation(None))
        assert result is None

    def test_returns_none_without_api_key(self):
        with patch("app.services.threat_intelligence.ip_reputation_client.get_settings") as mock_settings:
            mock_settings.return_value.abuseipdb_api_key = ""
            result = _run(check_ip_reputation("1.2.3.4"))
            assert result is None

    def test_blacklisted_high_confidence(self):
        response = _make_response(200, {
            "abuseConfidenceScore": 85,
            "countryCode": "RU",
            "isp": "Evil ISP",
            "isTor": False,
            "totalReports": 42,
        })
        mock_client = _make_mock_client(response)

        with patch("app.services.threat_intelligence.ip_reputation_client.get_settings") as mock_settings, \
             patch("app.services.threat_intelligence.ip_reputation_client.httpx.AsyncClient", return_value=mock_client):
            mock_settings.return_value.abuseipdb_api_key = "test-key"
            result = _run(check_ip_reputation("185.100.87.42"))

        assert result is not None
        assert result.ip_blacklisted is True
        assert result.abuse_confidence_score == 85
        assert result.country_code == "RU"
        assert result.country_risk_score == 1.0
        assert result.isp == "Evil ISP"
        assert result.total_reports == 42

    def test_clean_ip_low_confidence(self):
        response = _make_response(200, {
            "abuseConfidenceScore": 5,
            "countryCode": "US",
            "isp": "Google LLC",
            "isTor": False,
            "totalReports": 1,
        })
        mock_client = _make_mock_client(response)

        with patch("app.services.threat_intelligence.ip_reputation_client.get_settings") as mock_settings, \
             patch("app.services.threat_intelligence.ip_reputation_client.httpx.AsyncClient", return_value=mock_client):
            mock_settings.return_value.abuseipdb_api_key = "test-key"
            result = _run(check_ip_reputation("8.8.8.8"))

        assert result is not None
        assert result.ip_blacklisted is False
        assert result.abuse_confidence_score == 5
        assert result.country_risk_score == 0.0

    def test_returns_none_on_http_error(self):
        response = _make_response(429)
        mock_client = _make_mock_client(response)

        with patch("app.services.threat_intelligence.ip_reputation_client.get_settings") as mock_settings, \
             patch("app.services.threat_intelligence.ip_reputation_client.httpx.AsyncClient", return_value=mock_client):
            mock_settings.return_value.abuseipdb_api_key = "test-key"
            result = _run(check_ip_reputation("1.2.3.4"))

        assert result is None

    def test_returns_none_on_exception(self):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=Exception("Connection timeout"))

        with patch("app.services.threat_intelligence.ip_reputation_client.get_settings") as mock_settings, \
             patch("app.services.threat_intelligence.ip_reputation_client.httpx.AsyncClient", return_value=mock_client):
            mock_settings.return_value.abuseipdb_api_key = "test-key"
            result = _run(check_ip_reputation("1.2.3.4"))

        assert result is None

    def test_boundary_confidence_50_not_blacklisted(self):
        response = _make_response(200, {
            "abuseConfidenceScore": 50,
            "countryCode": "DE",
            "isp": "Hetzner",
            "isTor": False,
            "totalReports": 10,
        })
        mock_client = _make_mock_client(response)

        with patch("app.services.threat_intelligence.ip_reputation_client.get_settings") as mock_settings, \
             patch("app.services.threat_intelligence.ip_reputation_client.httpx.AsyncClient", return_value=mock_client):
            mock_settings.return_value.abuseipdb_api_key = "test-key"
            result = _run(check_ip_reputation("1.2.3.4"))

        assert result.ip_blacklisted is False  # 50 is not > 50

    def test_boundary_confidence_51_blacklisted(self):
        response = _make_response(200, {
            "abuseConfidenceScore": 51,
            "countryCode": "DE",
            "isp": "Hetzner",
            "isTor": False,
            "totalReports": 10,
        })
        mock_client = _make_mock_client(response)

        with patch("app.services.threat_intelligence.ip_reputation_client.get_settings") as mock_settings, \
             patch("app.services.threat_intelligence.ip_reputation_client.httpx.AsyncClient", return_value=mock_client):
            mock_settings.return_value.abuseipdb_api_key = "test-key"
            result = _run(check_ip_reputation("1.2.3.4"))

        assert result.ip_blacklisted is True  # 51 > 50


class TestHighRiskCountries:
    """Test country risk classification."""

    def test_known_high_risk_countries(self):
        assert "RU" in HIGH_RISK_COUNTRIES
        assert "CN" in HIGH_RISK_COUNTRIES
        assert "NG" in HIGH_RISK_COUNTRIES

    def test_safe_countries_not_included(self):
        assert "US" not in HIGH_RISK_COUNTRIES
        assert "GB" not in HIGH_RISK_COUNTRIES
        assert "DE" not in HIGH_RISK_COUNTRIES


class TestIpReputationResult:
    """Test default values of IpReputationResult."""

    def test_defaults(self):
        result = IpReputationResult()
        assert result.ip is None
        assert result.abuse_confidence_score == 0
        assert result.ip_blacklisted is False
        assert result.country_risk_score == 0.0
        assert result.is_tor is False
