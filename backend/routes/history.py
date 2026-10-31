"""
routes/history.py — GET /api/v1/history (authenticated users only).
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, Query

import models
from database import get_db
from routes.auth import get_current_user
from schemas import ScanHistoryItem, ScanHistoryResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["history"])


@router.get("/history", response_model=ScanHistoryResponse)
def get_history(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: dict = Depends(get_current_user),
) -> ScanHistoryResponse:
    """Return the authenticated user's scan history."""
    with get_db() as conn:
        rows = models.get_scans_for_user(conn, current_user["id"], limit=limit, offset=offset)

    items = [
        ScanHistoryItem(
            id=row["id"],
            url=row["url"],
            prediction=row["prediction"],
            risk_level=row["risk_level"],
            phishing_probability=row["phishing_probability"],
            model_version=row["model_version"],
            warnings=json.loads(row["warnings_json"] or "[]"),
            explanation=row["explanation"],
            source=row["source"],
            created_at=str(row["created_at"]),
        )
        for row in rows
    ]

    return ScanHistoryResponse(items=items, total=len(items))
