"""
routes/forum.py — Community forum: posts and replies (authenticated users).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status

import models
from database import get_db
from routes.auth import get_current_user
from schemas import (
    ForumPostCreate,
    ForumPostDetail,
    ForumPostResponse,
    ForumReplyCreate,
    ForumReplyResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/forum", tags=["forum"])


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _row_to_post(row) -> ForumPostResponse:
    return ForumPostResponse(
        id=row["id"],
        user_id=row["user_id"],
        username=row["username"],
        title=row["title"],
        body=row["body"],
        created_at=str(row["created_at"]),
    )


def _row_to_reply(row) -> ForumReplyResponse:
    return ForumReplyResponse(
        id=row["id"],
        post_id=row["post_id"],
        user_id=row["user_id"],
        username=row["username"],
        body=row["body"],
        created_at=str(row["created_at"]),
    )


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #

@router.get("/posts", response_model=list[ForumPostResponse])
def list_posts(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: dict = Depends(get_current_user),
) -> list[ForumPostResponse]:
    """List forum posts, newest first."""
    with get_db() as conn:
        rows = models.get_forum_posts(conn, limit=limit, offset=offset)
    return [_row_to_post(r) for r in rows]


@router.post("/posts", response_model=ForumPostResponse, status_code=status.HTTP_201_CREATED)
def create_post(
    body: ForumPostCreate,
    current_user: dict = Depends(get_current_user),
) -> ForumPostResponse:
    """Create a new forum post."""
    with get_db() as conn:
        post_id = models.insert_forum_post(conn, current_user["id"], body.title, body.body)
        row = models.get_forum_post(conn, post_id)
    return _row_to_post(row)


@router.get("/posts/{post_id}", response_model=ForumPostResponse)
def get_post(
    post_id: int,
    current_user: dict = Depends(get_current_user),
) -> ForumPostResponse:
    """Fetch a single forum post by ID."""
    with get_db() as conn:
        row = models.get_forum_post(conn, post_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")
    return _row_to_post(row)


@router.get("/posts/{post_id}/replies", response_model=list[ForumReplyResponse])
def list_replies(
    post_id: int,
    current_user: dict = Depends(get_current_user),
) -> list[ForumReplyResponse]:
    """List all replies for a forum post."""
    with get_db() as conn:
        post = models.get_forum_post(conn, post_id)
        if post is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")
        rows = models.get_forum_replies(conn, post_id)
    return [_row_to_reply(r) for r in rows]


@router.post(
    "/posts/{post_id}/replies",
    response_model=ForumReplyResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_reply(
    post_id: int,
    body: ForumReplyCreate,
    current_user: dict = Depends(get_current_user),
) -> ForumReplyResponse:
    """Add a reply to a forum post."""
    with get_db() as conn:
        post = models.get_forum_post(conn, post_id)
        if post is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")
        reply_id = models.insert_forum_reply(conn, post_id, current_user["id"], body.body)
        rows = models.get_forum_replies(conn, post_id)
        reply_row = next((r for r in rows if r["id"] == reply_id), None)
    if reply_row is None:
        raise HTTPException(status_code=500, detail="Reply created but could not be fetched")
    return _row_to_reply(reply_row)
