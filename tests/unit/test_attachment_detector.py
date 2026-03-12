"""
PhisMail — Attachment Risk Detector Tests
"""

import pytest
from app.services.attachment_analysis.attachment_risk_detector import (
    analyze_attachments,
    _detect_mime_mismatch,
)


class TestAnalyzeAttachments:
    """Test attachment risk detection."""

    def test_detects_executable(self):
        result = analyze_attachments([
            {"filename": "setup.exe", "content_type": "application/x-msdownload", "size": 1024, "sha256": "abc"},
        ])
        assert result.has_executable is True
        assert result.risk_score > 0

    def test_detects_script(self):
        result = analyze_attachments([
            {"filename": "payload.js", "content_type": "text/javascript", "size": 512, "sha256": "def"},
        ])
        assert result.has_script is True

    def test_detects_macro_document(self):
        result = analyze_attachments([
            {"filename": "report.docm", "content_type": "application/vnd.ms-word.document.macroEnabled.12", "size": 4096, "sha256": "ghi"},
        ])
        assert result.has_macro_document is True

    def test_detects_double_extension(self):
        result = analyze_attachments([
            {"filename": "invoice.pdf.exe", "content_type": "application/octet-stream", "size": 2048, "sha256": "jkl"},
        ])
        assert result.double_extension_detected is True
        assert result.has_executable is True

    def test_detects_archive(self):
        result = analyze_attachments([
            {"filename": "data.zip", "content_type": "application/zip", "size": 8192, "sha256": "mno"},
        ])
        assert result.has_archive is True

    def test_safe_attachment(self):
        result = analyze_attachments([
            {"filename": "photo.jpg", "content_type": "image/jpeg", "size": 50000, "sha256": "pqr"},
        ])
        assert result.has_executable is False
        assert result.has_script is False
        assert result.has_macro_document is False
        assert result.double_extension_detected is False
        assert result.risk_score == 0.0

    def test_empty_attachments(self):
        result = analyze_attachments([])
        assert result.attachment_count == 0
        assert result.risk_score == 0.0

    def test_multiple_risky_attachments(self, sample_attachments):
        result = analyze_attachments(sample_attachments)
        assert result.attachment_count == 2
        assert result.has_executable is True
        assert result.has_macro_document is True
        assert result.risk_score > 0.3

    def test_risk_score_capped_at_one(self):
        # Many risky attachments should still cap at 1.0
        attachments = [
            {"filename": f"file{i}.exe", "content_type": "application/octet-stream", "size": 1024, "sha256": f"hash{i}"}
            for i in range(5)
        ]
        result = analyze_attachments(attachments)
        assert result.risk_score <= 1.0


class TestMimeMismatch:
    """Test MIME type mismatch detection."""

    def test_pdf_mismatch(self):
        assert _detect_mime_mismatch(".pdf", "application/octet-stream") is True

    def test_pdf_correct(self):
        assert _detect_mime_mismatch(".pdf", "application/pdf") is False

    def test_unknown_extension(self):
        assert _detect_mime_mismatch(".xyz", "application/octet-stream") is False

    def test_jpg_mismatch(self):
        assert _detect_mime_mismatch(".jpg", "text/plain") is True
