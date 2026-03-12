"""
PhisMail — Test Configuration
Pytest fixtures and shared test utilities.
"""

import os
import sys
import pytest
from unittest.mock import MagicMock, patch

# Ensure app package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

# Mock settings before any app imports
_mock_settings = MagicMock()
_mock_settings.database_url = "sqlite:///:memory:"
_mock_settings.redis_url = "redis://localhost:6379/0"
_mock_settings.celery_broker_url = "redis://localhost:6379/1"
_mock_settings.celery_result_backend = "redis://localhost:6379/2"
_mock_settings.openphish_feed_url = "https://openphish.com/feed.txt"
_mock_settings.phishtank_api_key = ""
_mock_settings.urlhaus_auth_key = ""
_mock_settings.upload_max_size_mb = 5
_mock_settings.allowed_mime_types_list = ["message/rfc822"]
_mock_settings.rate_limit_default = "60/minute"
_mock_settings.cache_ttl_domain_intel = 86400
_mock_settings.cache_ttl_dns_records = 86400
_mock_settings.cache_ttl_threat_lookup = 86400
_mock_settings.ml_model_path = "/tmp/models"


@pytest.fixture(autouse=True)
def mock_settings(monkeypatch):
    """Mock settings for all tests."""
    with patch("app.core.config.get_settings", return_value=_mock_settings):
        yield _mock_settings


@pytest.fixture
def sample_eml_content():
    """Minimal valid .eml content for testing."""
    return b"""From: attacker@evil.com
Reply-To: phisher@malicious.net
Return-Path: <bounce@different.org>
To: victim@company.com
Subject: URGENT: Your account will be suspended
Date: Mon, 10 Mar 2025 03:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"
Authentication-Results: mx.company.com; spf=fail; dkim=fail; dmarc=fail
Received: from [185.100.87.42] by mx.company.com

--BOUNDARY
Content-Type: text/plain; charset="utf-8"

Dear Customer,

Your account has been locked. Click here immediately to verify your identity:
https://paypal-security.evil.ru/login?verify=true&session=abc123

Failure to act within 24 hours will result in permanent suspension.

Sincerely,
PayPal Security Team

--BOUNDARY
Content-Type: text/html; charset="utf-8"

<html>
<body>
<p>Dear Customer,</p>
<p>Your account has been <b>locked</b>.</p>
<a href="https://paypal-security.evil.ru/login?verify=true&session=abc123">Click here to verify</a>
<script>alert('xss')</script>
<div style="display:none"><a href="https://hidden-tracker.com/t">hidden</a></div>
</body>
</html>

--BOUNDARY
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Disposition: attachment; filename="invoice.pdf.exe"

FAKE_BINARY_CONTENT

--BOUNDARY--
"""


@pytest.fixture
def sample_headers():
    """Sample email headers for testing."""
    return {
        "From": "attacker@evil.com",
        "Reply-To": "phisher@malicious.net",
        "Return-Path": "<bounce@different.org>",
        "Subject": "URGENT: Your account will be suspended",
        "Authentication-Results": "mx.company.com; spf=fail; dkim=fail; dmarc=fail",
        "Received": "from [185.100.87.42] by mx.company.com",
    }


@pytest.fixture
def sample_attachments():
    """Sample attachment metadata for testing."""
    return [
        {
            "filename": "invoice.pdf.exe",
            "content_type": "application/octet-stream",
            "size": 1024,
            "sha256": "abc123",
        },
        {
            "filename": "report.docm",
            "content_type": "application/vnd.ms-word.document.macroEnabled.12",
            "size": 2048,
            "sha256": "def456",
        },
    ]
