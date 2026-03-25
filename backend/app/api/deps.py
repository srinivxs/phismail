"""
PhisMail — Auth Dependencies
Reusable FastAPI dependencies for route protection.
"""

from typing import Optional
from fastapi import Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services.auth_service import decode_token, get_user_by_id
from app.models.models import User


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Require a valid JWT access token. Returns the User or raises 401."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header.split(" ", 1)[1]
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = get_user_by_id(db, payload["sub"])
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return user


def get_optional_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    """Optionally resolve a user from JWT. Returns None if no valid token."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    token = auth_header.split(" ", 1)[1]
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        return None

    return get_user_by_id(db, payload["sub"])
