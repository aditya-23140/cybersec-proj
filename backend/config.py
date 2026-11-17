"""
config.py — Application settings loaded from environment variables.
All values have sensible defaults for development; in production
set JWT_SECRET_KEY explicitly.
"""

import os
import secrets
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).with_name(".env"))
except ImportError:
    pass

# --------------------------------------------------------------------------- #
# ML / model
# --------------------------------------------------------------------------- #
def _resolve_bundle_path() -> str:
    env_path = os.getenv("ML_BUNDLE_PATH")
    if env_path and Path(env_path).exists():
        return env_path
    repo_root = Path(__file__).resolve().parents[1]
    candidates = [
        repo_root / "ml" / "v2" / "artifacts" / "bundle.pkl.gz",
        repo_root / "ml" / "bundle.pkl.gz",
        repo_root / "ml" / "artifacts" / "bundle.pkl.gz",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return str(candidates[0])

ML_BUNDLE_PATH: str = _resolve_bundle_path()
ALLOW_UNGATED_MODEL: bool = os.getenv("ALLOW_UNGATED_MODEL", "true").lower() == "true"

# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #
DATABASE_PATH: str = os.getenv("DATABASE_PATH", "phishing.db")

# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #
JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
JWT_ALGORITHM: str = "HS256"
JWT_EXPIRY_HOURS: int = 24

# --------------------------------------------------------------------------- #
# CORS
# --------------------------------------------------------------------------- #
CORS_ORIGINS: list[str] = os.getenv(
    "CORS_ORIGINS", "http://localhost:3000"
).split(",")

# --------------------------------------------------------------------------- #
# Server-side page fetch (hybrid scanning)
# --------------------------------------------------------------------------- #
ENABLE_PAGE_FETCH: bool = os.getenv("ENABLE_PAGE_FETCH", "false").lower() == "true"
PAGE_FETCH_TIMEOUT: float = float(os.getenv("PAGE_FETCH_TIMEOUT", "5.0"))
PAGE_FETCH_MAX_BYTES: int = int(os.getenv("PAGE_FETCH_MAX_BYTES", "300000"))

# --------------------------------------------------------------------------- #
# Model metadata
# --------------------------------------------------------------------------- #
MODEL_VERSION: str = "2.0.0-dev"
