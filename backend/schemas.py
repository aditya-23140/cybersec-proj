"""
schemas.py — Pydantic request and response models for the API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


# --------------------------------------------------------------------------- #
# Prediction
# --------------------------------------------------------------------------- #

class PredictRequest(BaseModel):
    url: str = Field(..., min_length=1, description="URL to analyse")

    @field_validator("url")
    @classmethod
    def url_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("URL must not be empty or whitespace")
        return v.strip()


class PredictResponse(BaseModel):
    request_id: str
    url: str
    prediction: str               # "benign" | "phishing"
    risk_level: str               # "safe" | "suspicious" | "dangerous"
    phishing_probability: float = Field(ge=0.0, le=1.0)
    model_version: str
    warnings: list[str]
    explanation: str
    source: str


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., min_length=5, max_length=254)
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("username")
    @classmethod
    def username_alphanum(cls, v: str) -> str:
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError(
                "Username may only contain letters, digits, underscores, or hyphens"
            )
        return v.lower()

    @field_validator("email")
    @classmethod
    def email_has_at(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError("Invalid email address")
        return v.lower()


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 86400  # seconds


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_at: str


# --------------------------------------------------------------------------- #
# Scan history
# --------------------------------------------------------------------------- #

class ScanHistoryItem(BaseModel):
    id: int
    url: str
    prediction: str
    risk_level: str
    phishing_probability: float = Field(ge=0.0, le=1.0)
    model_version: str
    warnings: list[str]
    explanation: str | None
    source: str
    created_at: str


class ScanHistoryResponse(BaseModel):
    items: list[ScanHistoryItem]
    total: int


# --------------------------------------------------------------------------- #
# Allowlist
# --------------------------------------------------------------------------- #

class AllowlistCreateRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)
    notes: str | None = Field(None, max_length=500)

    @field_validator("domain")
    @classmethod
    def normalise_domain(cls, v: str) -> str:
        return v.strip().lower().lstrip("www.") if v.startswith("www.") else v.strip().lower()


class AllowlistEntry(BaseModel):
    id: int
    domain: str
    notes: str | None
    created_at: str


class AllowlistResponse(BaseModel):
    items: list[AllowlistEntry]


# --------------------------------------------------------------------------- #
# Blocklist
# --------------------------------------------------------------------------- #

class BlocklistCreateRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)
    notes: str | None = Field(None, max_length=500)

    @field_validator("domain")
    @classmethod
    def normalise_domain(cls, v: str) -> str:
        return v.strip().lower().lstrip("www.") if v.startswith("www.") else v.strip().lower()


class BlocklistEntry(BaseModel):
    id: int
    domain: str
    notes: str | None
    created_at: str


class BlocklistResponse(BaseModel):
    items: list[BlocklistEntry]


# --------------------------------------------------------------------------- #
# Forum
# --------------------------------------------------------------------------- #

class ForumPostCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    body: str = Field(..., min_length=1, max_length=5000)


class ForumPostResponse(BaseModel):
    id: int
    user_id: int
    username: str
    title: str
    body: str
    created_at: str


class ForumReplyCreate(BaseModel):
    body: str = Field(..., min_length=1, max_length=5000)


class ForumReplyResponse(BaseModel):
    id: int
    post_id: int
    user_id: int
    username: str
    body: str
    created_at: str


class ForumPostDetail(BaseModel):
    post: ForumPostResponse
    replies: list[ForumReplyResponse]


# --------------------------------------------------------------------------- #
# Stats
# --------------------------------------------------------------------------- #

class StatsResponse(BaseModel):
    total_scans: int
    benign_count: int
    phishing_count: int
    dangerous_count: int
    suspicious_count: int
    safe_count: int
    recent_scans_24h: int
    model_version: str
    last_scan_at: str | None


# --------------------------------------------------------------------------- #
# Health / model info
# --------------------------------------------------------------------------- #

class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    database: str
    version: str


class ModelInfoResponse(BaseModel):
    model_version: str
    artifacts_dir: str
    model_loaded: bool
    threshold_config: dict[str, Any] | None


# --------------------------------------------------------------------------- #
# Error
# --------------------------------------------------------------------------- #

class ErrorResponse(BaseModel):
    error: str
    detail: str
