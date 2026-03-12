"""
PhisMail — Authentication Stubs
Placeholder auth layer for future API key / JWT implementation.

NOTE: All functions in this module are STUBS. No real key validation or
token verification is performed. The intent is to establish the FastAPI
dependency interface so that routes can be written against it today and
the underlying implementation can be swapped in without touching route
handlers.

When real authentication is ready:
1. Set ``AuthConfig.AUTH_ENABLED = True``.
2. Implement key-lookup / JWT-verification logic inside
   ``require_api_key`` (and optionally ``optional_api_key``).
3. Remove the ``settings.debug`` bypass in ``require_api_key``.
"""

from typing import Optional

from fastapi import Header, HTTPException, status

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

# The HTTP header name expected to carry an API key.
API_KEY_HEADER = "X-API-Key"


# ---------------------------------------------------------------------------
# Dependency functions
# ---------------------------------------------------------------------------


async def optional_api_key(
    x_api_key: Optional[str] = Header(None, alias=API_KEY_HEADER),
) -> Optional[str]:
    """FastAPI dependency — accept an optional API key without validation.

    Designed for endpoints that should work anonymously but can optionally
    accept a key for rate-limit or quota differentiation.

    Args:
        x_api_key: Value of the ``X-API-Key`` request header, or ``None``
            if the header is absent.

    Returns:
        The raw key string as received, or ``None``.
    """
    logger.debug("auth_check_skipped", key_present=x_api_key is not None)
    return x_api_key


async def require_api_key(
    x_api_key: Optional[str] = Header(None, alias=API_KEY_HEADER),
) -> str:
    """FastAPI dependency — require a non-empty API key header.

    Behaviour varies by ``settings.debug``:

    * **Debug mode** (``settings.debug = True``): all requests pass
      regardless of whether a key is present.  A warning is logged to
      make this visible in development logs.
    * **Production mode** (``settings.debug = False``): requests without
      the ``X-API-Key`` header are rejected with HTTP 401.  Keys that
      *are* present are returned as-is — actual key validation is not yet
      implemented.

    Args:
        x_api_key: Value of the ``X-API-Key`` request header, or ``None``
            if absent.

    Returns:
        The API key string.

    Raises:
        HTTPException: 401 Unauthorized when no key is supplied in
            non-debug mode.
    """
    if settings.debug:
        logger.warning(
            "api_key_validation_not_enforced",
            reason="debug mode is enabled — all requests pass",
        )
        # Return a sentinel string so callers always get a str, not None.
        return x_api_key or ""

    if not x_api_key:
        logger.warning(
            "api_key_missing",
            detail="request rejected — X-API-Key header not provided",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required. Provide a valid X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # TODO: validate key against the database / secrets store.
    logger.debug("api_key_received_no_validation", key_prefix=x_api_key[:4] + "…")
    return x_api_key


# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------


class AuthConfig:
    """Static configuration constants for the authentication layer.

    These values centralise auth-related tunables so they can be found
    and changed in one place when real authentication is implemented.
    """

    AUTH_ENABLED: bool = False  # Toggle when implementing real auth
    API_KEY_MIN_LENGTH: int = 32
    TOKEN_EXPIRE_MINUTES: int = 60
