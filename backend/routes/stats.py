"""
routes/stats.py — Dashboard statistics from actual database records.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter

import config
import models
from database import get_db
from schemas import StatsResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["stats"])


@router.get("/stats", response_model=StatsResponse)
def get_stats() -> StatsResponse:
    """Return aggregate scan statistics from the database. No hardcoded values."""
    with get_db() as conn:
        stats = models.get_stats(conn)

    return StatsResponse(
        total_scans=stats.get("total_scans") or 0,
        benign_count=stats.get("benign_count") or 0,
        phishing_count=stats.get("phishing_count") or 0,
        dangerous_count=stats.get("dangerous_count") or 0,
        suspicious_count=stats.get("suspicious_count") or 0,
        safe_count=stats.get("safe_count") or 0,
        recent_scans_24h=stats.get("recent_scans_24h") or 0,
        model_version=config.MODEL_VERSION,
        last_scan_at=stats.get("last_scan_at"),
    )
