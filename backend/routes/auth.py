"""
routes/auth.py — Registration, login, logout, and current-user endpoints.
"""

from __future__ import annotations

import logging
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request, status
from jose import JWTError

import models
from database import get_db
from schemas import LoginRequest, RegisterRequest, TokenResponse, UserResponse
from services.auth_service import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])


# --------------------------------------------------------------------------- #
# Dependency: current authenticated user
# --------------------------------------------------------------------------- #

def get_current_user(request: Request) -> dict:
    """
    FastAPI dependency that extracts and validates the Bearer JWT.
    Returns the user row dict or raises 401.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise credentials_exception

    token = auth_header.removeprefix("Bearer ").strip()
    try:
        payload = decode_access_token(token)
        user_id: int | None = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        user_id = int(user_id)
    except (JWTError, ValueError):
        raise credentials_exception

    with get_db() as conn:
        user = models.get_user_by_id(conn, user_id)
        if user is None:
            raise credentials_exception
        return dict(user)


def get_optional_user(request: Request) -> dict | None:
    """Like get_current_user but returns None instead of raising 401."""
    try:
        return get_current_user(request)
    except HTTPException:
        return None


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest) -> UserResponse:
    """Create a new user account."""
    with get_db() as conn:
        # Check for existing username / email
        if models.get_user_by_username(conn, body.username):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already taken",
            )
        if models.get_user_by_email(conn, body.email):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered",
            )

        try:
            user_id = models.create_user(
                conn,
                username=body.username,
                email=body.email,
                password_hash=hash_password(body.password),
            )
            user = models.get_user_by_id(conn, user_id)
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username or email already exists",
            )

    return UserResponse(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        role=user["role"],
        created_at=str(user["created_at"]),
    )


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest) -> TokenResponse:
    """Authenticate and return a JWT."""
    with get_db() as conn:
        user = models.get_user_by_username(conn, body.username.lower())

    if user is None or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    token = create_access_token({"sub": str(user["id"])})
    return TokenResponse(access_token=token)


@router.post("/logout", status_code=status.HTTP_200_OK)
def logout() -> dict:
    """
    Logout is handled client-side by discarding the token.
    This endpoint exists for API completeness.
    """
    return {"message": "Logged out. Please discard your token."}


@router.get("/me", response_model=UserResponse)
def me(current_user: dict = Depends(get_current_user)) -> UserResponse:
    """Return the currently authenticated user's profile."""
    return UserResponse(
        id=current_user["id"],
        username=current_user["username"],
        email=current_user["email"],
        role=current_user["role"],
        created_at=str(current_user["created_at"]),
    )
