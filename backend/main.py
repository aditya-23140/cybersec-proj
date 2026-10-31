"""
main.py — FastAPI application factory.

Startup order:
  1. Initialise SQLite schema (and admin seed) via init_db().
  2. Load PhishingPredictor from ml/ artifacts via load_predictor().
  3. Mount all routers under /api/v1.

CORS is restricted to CORS_ORIGINS from config (default: localhost:3000).
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import config

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Lifespan: startup / shutdown
# ─────────────────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise DB and load model on startup."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Database
    from database import init_db
    init_db()

    # ML model
    from services.predictor import load_predictor
    load_predictor()

    yield
    # Nothing to clean up for SQLite / XGBoost


# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="PhishGuard API",
    description="URL phishing detection powered by XGBoost.",
    version="1.0.0",
    lifespan=lifespan,
)

# ── CORS ────────────────────────────────────────────────────────────────────
# Allow the extension (chrome-extension://) and the Next.js frontend.
allowed_origins = list(config.CORS_ORIGINS) + ["chrome-extension://*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# ── Routers ──────────────────────────────────────────────────────────────────
from routes.auth import router as auth_router
from routes.forum import router as forum_router
from routes.history import router as history_router
from routes.lists import router as lists_router
from routes.predict import router as predict_router
from routes.stats import router as stats_router

PREFIX = "/api/v1"

app.include_router(predict_router, prefix=PREFIX)
app.include_router(auth_router, prefix=PREFIX)
app.include_router(history_router, prefix=PREFIX)
app.include_router(lists_router, prefix=PREFIX)
app.include_router(forum_router, prefix=PREFIX)
app.include_router(stats_router, prefix=PREFIX)


# ── Health & model-info (root-level convenience) ─────────────────────────────

@app.get(f"{PREFIX}/health")
def health():
    from services.predictor import is_model_loaded
    from database import get_connection
    db_ok = "ok"
    try:
        conn = get_connection()
        conn.execute("SELECT 1")
        conn.close()
    except Exception:
        db_ok = "error"

    return {
        "status": "ok" if is_model_loaded() else "degraded",
        "model_loaded": is_model_loaded(),
        "database": db_ok,
        "version": "1.0.0",
    }


@app.get(f"{PREFIX}/model-info")
def model_info():
    from services.predictor import get_threshold_config, is_model_loaded
    return {
        "model_version": config.MODEL_VERSION,
        "artifacts_dir": config.ML_ARTIFACTS_DIR,
        "model_loaded": is_model_loaded(),
        "threshold_config": get_threshold_config(),
    }
