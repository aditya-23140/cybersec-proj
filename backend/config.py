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
ENABLE_NETWORK_ENRICHMENT: bool = (
    os.getenv("ENABLE_NETWORK_ENRICHMENT", "true").lower() == "true"
)
ENRICHMENT_TIMEOUT_SECONDS: float = float(
    os.getenv("ENRICHMENT_TIMEOUT_SECONDS", "5")
)
URLHAUS_ENABLED: bool = os.getenv("URLHAUS_ENABLED", "false").lower() == "true"
URLHAUS_AUTH_KEY: str = os.getenv("URLHAUS_AUTH_KEY", "")
URLHAUS_LOOKUP_URL: str = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_LOOKUP_URL: str = "https://urlhaus-api.abuse.ch/v1/host/"

# --------------------------------------------------------------------------- #
# Model metadata
# --------------------------------------------------------------------------- #
MODEL_VERSION: str = "1.1.0"
