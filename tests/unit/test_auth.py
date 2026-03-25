"""
PhisMail — Authentication Unit Tests
Tests for auth service, password hashing, JWT tokens, and API routes.
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from app.services.auth_service import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.schemas.auth_schemas import SignupRequest, LoginRequest


# =============================================================================
# Password Hashing
# =============================================================================


class TestPasswordHashing:
    def test_hash_password_returns_string(self):
        hashed = hash_password("TestPass123")
        assert isinstance(hashed, str)
        assert len(hashed) > 20

    def test_hash_password_not_plaintext(self):
        password = "MySecretPass1"
        hashed = hash_password(password)
        assert hashed != password

    def test_verify_password_correct(self):
        password = "CorrectHorse42"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        hashed = hash_password("RightPassword1")
        assert verify_password("WrongPassword1", hashed) is False

    def test_different_hashes_for_same_password(self):
        password = "SamePassword1"
        h1 = hash_password(password)
        h2 = hash_password(password)
        # bcrypt generates different salts
        assert h1 != h2
        # But both verify correctly
        assert verify_password(password, h1) is True
        assert verify_password(password, h2) is True


# =============================================================================
# JWT Tokens
# =============================================================================


class TestJWTTokens:
    def test_create_access_token(self):
        token = create_access_token("user-123")
        assert isinstance(token, str)
        assert len(token) > 20

    def test_create_refresh_token(self):
        token = create_refresh_token("user-456")
        assert isinstance(token, str)
        assert len(token) > 20

    def test_decode_access_token(self):
        token = create_access_token("user-789")
        payload = decode_token(token)
        assert payload is not None
        assert payload["sub"] == "user-789"
        assert payload["type"] == "access"

    def test_decode_refresh_token(self):
        token = create_refresh_token("user-abc")
        payload = decode_token(token)
        assert payload is not None
        assert payload["sub"] == "user-abc"
        assert payload["type"] == "refresh"

    def test_decode_invalid_token_returns_none(self):
        payload = decode_token("not-a-valid-jwt-token")
        assert payload is None

    def test_decode_empty_token_returns_none(self):
        payload = decode_token("")
        assert payload is None

    def test_tokens_are_different(self):
        access = create_access_token("user-x")
        refresh = create_refresh_token("user-x")
        assert access != refresh


# =============================================================================
# Signup Schema Validation
# =============================================================================


class TestSignupValidation:
    def test_valid_signup(self):
        req = SignupRequest(email="test@example.com", password="ValidPass1")
        assert req.email == "test@example.com"

    def test_email_normalized_to_lowercase(self):
        req = SignupRequest(email="Test@EXAMPLE.com", password="ValidPass1")
        assert req.email == "test@example.com"

    def test_invalid_email_rejected(self):
        with pytest.raises(Exception):
            SignupRequest(email="not-an-email", password="ValidPass1")

    def test_short_password_rejected(self):
        with pytest.raises(Exception):
            SignupRequest(email="test@example.com", password="Short1")

    def test_password_needs_uppercase(self):
        with pytest.raises(Exception):
            SignupRequest(email="test@example.com", password="nouppercase1")

    def test_password_needs_lowercase(self):
        with pytest.raises(Exception):
            SignupRequest(email="test@example.com", password="NOLOWERCASE1")

    def test_password_needs_digit(self):
        with pytest.raises(Exception):
            SignupRequest(email="test@example.com", password="NoDigitHere")

    def test_valid_complex_password(self):
        req = SignupRequest(email="a@b.com", password="C0mpl3xP@ss!")
        assert req.password == "C0mpl3xP@ss!"


# =============================================================================
# Login Schema Validation
# =============================================================================


class TestLoginValidation:
    def test_valid_login(self):
        req = LoginRequest(email="test@example.com", password="anypassword")
        assert req.email == "test@example.com"

    def test_empty_password_rejected(self):
        with pytest.raises(Exception):
            LoginRequest(email="test@example.com", password="")
