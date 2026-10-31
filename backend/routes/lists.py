"""
routes/lists.py — Allowlist and blocklist CRUD (authenticated users).
"""

from __future__ import annotations

import logging
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, status

import models
from database import get_db
from routes.auth import get_current_user
from schemas import (
    AllowlistCreateRequest,
    AllowlistEntry,
    AllowlistResponse,
    BlocklistCreateRequest,
    BlocklistEntry,
    BlocklistResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["lists"])


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _row_to_allowlist_entry(row) -> AllowlistEntry:
    return AllowlistEntry(
        id=row["id"],
        domain=row["domain"],
        notes=row["notes"],
        created_at=str(row["created_at"]),
    )


def _row_to_blocklist_entry(row) -> BlocklistEntry:
    return BlocklistEntry(
        id=row["id"],
        domain=row["domain"],
        notes=row["notes"],
        created_at=str(row["created_at"]),
    )


# =========================================================================== #
# Allowlist
# =========================================================================== #

@router.get("/allowlist", response_model=AllowlistResponse)
def list_allowlist(
    current_user: dict = Depends(get_current_user),
) -> AllowlistResponse:
    """Return all allowlist entries for the current user."""
    with get_db() as conn:
        rows = models.get_allowlist(conn, current_user["id"])
    return AllowlistResponse(items=[_row_to_allowlist_entry(r) for r in rows])


@router.post(
    "/allowlist",
    response_model=AllowlistEntry,
    status_code=status.HTTP_201_CREATED,
)
def add_allowlist(
    body: AllowlistCreateRequest,
    current_user: dict = Depends(get_current_user),
) -> AllowlistEntry:
    """Add a domain to the current user's allowlist."""
    with get_db() as conn:
        try:
            entry_id = models.insert_allowlist(
                conn, current_user["id"], body.domain, body.notes
            )
            row = models.get_allowlist_entry(conn, entry_id, current_user["id"])
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Domain '{body.domain}' is already in your allowlist",
            )
    return _row_to_allowlist_entry(row)


@router.delete("/allowlist/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_allowlist(
    entry_id: int,
    current_user: dict = Depends(get_current_user),
) -> None:
    """Remove an entry from the current user's allowlist."""
    with get_db() as conn:
        deleted = models.delete_allowlist_entry(conn, entry_id, current_user["id"])
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Allowlist entry not found",
        )


# =========================================================================== #
# Blocklist
# =========================================================================== #

@router.get("/blocklist", response_model=BlocklistResponse)
def list_blocklist(
    current_user: dict = Depends(get_current_user),
) -> BlocklistResponse:
    """Return all blocklist entries for the current user."""
    with get_db() as conn:
        rows = models.get_blocklist(conn, current_user["id"])
    return BlocklistResponse(items=[_row_to_blocklist_entry(r) for r in rows])


@router.post(
    "/blocklist",
    response_model=BlocklistEntry,
    status_code=status.HTTP_201_CREATED,
)
def add_blocklist(
    body: BlocklistCreateRequest,
    current_user: dict = Depends(get_current_user),
) -> BlocklistEntry:
    """Add a domain to the current user's blocklist."""
    with get_db() as conn:
        try:
            entry_id = models.insert_blocklist(
                conn, current_user["id"], body.domain, body.notes
            )
            row = models.get_blocklist_entry(conn, entry_id, current_user["id"])
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Domain '{body.domain}' is already in your blocklist",
            )
    return _row_to_blocklist_entry(row)


@router.delete("/blocklist/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_blocklist(
    entry_id: int,
    current_user: dict = Depends(get_current_user),
) -> None:
    """Remove an entry from the current user's blocklist."""
    with get_db() as conn:
        deleted = models.delete_blocklist_entry(conn, entry_id, current_user["id"])
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Blocklist entry not found",
        )
