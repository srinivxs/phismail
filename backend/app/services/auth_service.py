"""
PhisMail — Authentication Service
Password hashing, JWT token management, and Google OAuth verification.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import jwt, JWTError
from passlib.context import CryptContext
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.models import User, AuthProvider

logger = get_logger(__name__)
settings = get_settings()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# =============================================================================
# Password Hashing
# =============================================================================

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# =============================================================================
# JWT Tokens
# =============================================================================

def create_access_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    payload = {"sub": user_id, "exp": expire, "type": "access"}
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_token_expire_days)
    payload = {"sub": user_id, "exp": expire, "type": "refresh"}
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        return payload
    except JWTError:
        return None


# =============================================================================
# Google OAuth Verification
# =============================================================================

def verify_google_token(token: str) -> Optional[dict]:
    """Verify a Google ID token and return user info dict or None."""
    try:
        idinfo = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            settings.google_client_id,
        )
        if idinfo.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
            return None
        return {
            "sub": idinfo["sub"],
            "email": idinfo["email"],
            "name": idinfo.get("name"),
            "picture": idinfo.get("picture"),
        }
    except Exception as e:
        logger.warning("google_token_verification_failed", error=str(e))
        return None


# =============================================================================
# User CRUD
# =============================================================================

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()


def get_user_by_id(db: Session, user_id: str) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()


def get_user_by_google_sub(db: Session, google_sub: str) -> Optional[User]:
    return db.query(User).filter(User.google_sub == google_sub).first()


def create_local_user(db: Session, email: str, password: str, display_name: Optional[str] = None) -> User:
    user = User(
        email=email.lower().strip(),
        hashed_password=hash_password(password),
        display_name=display_name or email.split("@")[0],
        auth_provider=AuthProvider.LOCAL,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def create_or_update_google_user(db: Session, google_info: dict) -> User:
    user = get_user_by_google_sub(db, google_info["sub"])
    if user:
        user.last_login_at = datetime.utcnow()
        user.display_name = google_info.get("name") or user.display_name
        user.avatar_url = google_info.get("picture") or user.avatar_url
        db.commit()
        db.refresh(user)
        return user

    # Check if email already exists (local account) — link it
    user = get_user_by_email(db, google_info["email"])
    if user:
        user.google_sub = google_info["sub"]
        user.auth_provider = AuthProvider.GOOGLE
        user.avatar_url = google_info.get("picture")
        user.last_login_at = datetime.utcnow()
        db.commit()
        db.refresh(user)
        return user

    # New user
    user = User(
        email=google_info["email"].lower().strip(),
        display_name=google_info.get("name") or google_info["email"].split("@")[0],
        google_sub=google_info["sub"],
        auth_provider=AuthProvider.GOOGLE,
        avatar_url=google_info.get("picture"),
        last_login_at=datetime.utcnow(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
