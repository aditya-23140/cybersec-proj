"""
services/auth_service.py — Password hashing and JWT creation/verification.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt

if not hasattr(bcrypt, "__about__"):
    class _About:
        __version__ = getattr(bcrypt, "__version__", "5.0.0")
    bcrypt.__about__ = _About()
_orig_hashpw = bcrypt.hashpw
def _safe_hashpw(password, salt):
    if isinstance(password, bytes) and len(password) > 72:
        password = password[:72]
    return _orig_hashpw(password, salt)
bcrypt.hashpw = _safe_hashpw

from jose import JWTError, jwt
from passlib.context import CryptContext

import config

logger = logging.getLogger(__name__)

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# --------------------------------------------------------------------------- #
# Password helpers
# --------------------------------------------------------------------------- #

def hash_password(plain: str) -> str:
    """Return a bcrypt hash of *plain*."""
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches *hashed*."""
    return _pwd_context.verify(plain, hashed)


# --------------------------------------------------------------------------- #
# JWT helpers
# --------------------------------------------------------------------------- #

def create_access_token(data: dict[str, Any]) -> str:
    """Create a signed JWT that expires in JWT_EXPIRY_HOURS hours."""
    payload = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(hours=config.JWT_EXPIRY_HOURS)
    payload["exp"] = expire
    return jwt.encode(payload, config.JWT_SECRET_KEY, algorithm=config.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and verify a JWT.

    Raises:
        JWTError: if the token is invalid or expired.
    """
    return jwt.decode(
        token,
        config.JWT_SECRET_KEY,
        algorithms=[config.JWT_ALGORITHM],
    )
