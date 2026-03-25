"""
PhisMail — Authentication API Routes
Signup, login, Google OAuth, token refresh, logout, and current user.
"""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.logging import get_logger
from app.schemas.auth_schemas import (
    SignupRequest,
    LoginRequest,
    GoogleLoginRequest,
    AuthResponse,
    UserResponse,
    TokenRefreshResponse,
)
from app.services.auth_service import (
    get_user_by_email,
    get_user_by_id,
    create_local_user,
    create_or_update_google_user,
    verify_password,
    verify_google_token,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.core.config import get_settings

logger = get_logger(__name__)
settings = get_settings()
router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

REFRESH_COOKIE = "phismail_refresh_token"
COOKIE_MAX_AGE = settings.jwt_refresh_token_expire_days * 86400


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=token,
        httponly=True,
        secure=False,  # set True in production with HTTPS
        samesite="lax",
        max_age=COOKIE_MAX_AGE,
        path="/api/v1/auth",
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(key=REFRESH_COOKIE, path="/api/v1/auth")


# =============================================================================
# Signup
# =============================================================================

@router.post("/signup", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def signup(body: SignupRequest, response: Response, db: Session = Depends(get_db)):
    existing = get_user_by_email(db, body.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    user = create_local_user(db, body.email, body.password, body.display_name)
    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)
    _set_refresh_cookie(response, refresh_token)

    logger.info("user_signup", user_id=user.id, email=user.email)
    return AuthResponse(
        access_token=access_token,
        user=UserResponse.model_validate(user),
    )


# =============================================================================
# Login
# =============================================================================

@router.post("/login", response_model=AuthResponse)
def login(body: LoginRequest, response: Response, db: Session = Depends(get_db)):
    user = get_user_by_email(db, body.email.lower().strip())
    if not user or not user.hashed_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    user.last_login_at = datetime.utcnow()
    db.commit()

    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)
    _set_refresh_cookie(response, refresh_token)

    logger.info("user_login", user_id=user.id)
    return AuthResponse(
        access_token=access_token,
        user=UserResponse.model_validate(user),
    )


# =============================================================================
# Google Login
# =============================================================================

@router.post("/google", response_model=AuthResponse)
def google_login(body: GoogleLoginRequest, response: Response, db: Session = Depends(get_db)):
    if not settings.google_client_id:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Google OAuth is not configured",
        )

    google_info = verify_google_token(body.credential)
    if not google_info:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google credential",
        )

    user = create_or_update_google_user(db, google_info)
    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)
    _set_refresh_cookie(response, refresh_token)

    logger.info("user_google_login", user_id=user.id, email=user.email)
    return AuthResponse(
        access_token=access_token,
        user=UserResponse.model_validate(user),
    )


# =============================================================================
# Refresh Token
# =============================================================================

@router.post("/refresh", response_model=TokenRefreshResponse)
def refresh_token(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get(REFRESH_COOKIE)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No refresh token")

    payload = decode_token(token)
    if not payload or payload.get("type") != "refresh":
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    user = get_user_by_id(db, payload["sub"])
    if not user or not user.is_active:
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    new_access = create_access_token(user.id)
    new_refresh = create_refresh_token(user.id)
    _set_refresh_cookie(response, new_refresh)

    return TokenRefreshResponse(access_token=new_access)


# =============================================================================
# Current User
# =============================================================================

@router.get("/me", response_model=UserResponse)
def get_current_user_route(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    token = auth_header.split(" ", 1)[1]
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = get_user_by_id(db, payload["sub"])
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return UserResponse.model_validate(user)


# =============================================================================
# Logout
# =============================================================================

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(response: Response):
    _clear_refresh_cookie(response)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
