"""
config.py — Application settings loaded from environment variables.
All values have sensible defaults for development; in production
set JWT_SECRET_KEY explicitly.
"""

import os
import secrets

# --------------------------------------------------------------------------- #
# ML / model
# --------------------------------------------------------------------------- #
ML_ARTIFACTS_DIR: str = os.getenv("ML_ARTIFACTS_DIR", "../ml/artifacts")

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
# Feature flags
# --------------------------------------------------------------------------- #
ENABLE_DNS_ENRICHMENT: bool = (
    os.getenv("ENABLE_DNS_ENRICHMENT", "false").lower() == "true"
)

# --------------------------------------------------------------------------- #
# Model metadata
# --------------------------------------------------------------------------- #
MODEL_VERSION: str = "1.0.0"
