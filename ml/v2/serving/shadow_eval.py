"""
ml/v2/serving/shadow_eval.py — Shadow evaluation, drift detection, and feedback loop.

Implements:
  - log_verdict(url_hash, score, label, mode, timestamp)
  - run_weekly_drift_check(fresh_legit_urls) -> dict
  - report_feedback(url_hash, correct_label) -> None

Designed for non-blocking shadow evaluation in production.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default shadow log path
_SHADOW_LOG_DIR = Path(__file__).resolve().parent / "shadow_logs"


def hash_url(url: str) -> str:
    """Compute salted or standard SHA256 hex digest of a URL."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def log_verdict(
    url_hash: str,
    score: float,
    label: str,
    mode: str = "url-only",
    timestamp: str | None = None,
    log_dir: str | Path | None = None,
) -> None:
    """
    Log inference verdicts and confidence scores to a persistent shadow log.

    In production: logs to Kafka / S3 / BigQuery for offline drift analysis.
    Here: writes newline-delimited JSON locally or logs at INFO level.
    """
    ts = timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()
    record = {
        "url_hash": url_hash,
        "score": score,
        "label": label,
        "mode": mode,
        "timestamp": ts,
    }

    target_dir = Path(log_dir) if log_dir else _SHADOW_LOG_DIR
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        date_str = ts.split("T")[0]
        log_file = target_dir / f"shadow_verdicts_{date_str}.jsonl"
        with log_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception as exc:
        # Shadow logging must never fail the request
        logger.warning("Failed to write shadow verdict log: %s", exc)

    logger.debug("Shadow verdict logged: hash=%s label=%s score=%.4f", url_hash, label, score)


def run_weekly_drift_check(
    fresh_legit_urls: list[str],
    detector: Any = None,
    max_acceptable_fpr: float = 0.02,
) -> dict[str, Any]:
    """
    Weekly automated drift detection against newly collected legitimate URLs.

    Evaluates whether the false positive rate on recent legitimate browsing
    has drifted beyond acceptable thresholds (e.g. > 2%).

    Returns:
        dict with keys:
          - sample_size: int
          - flagged_count: int
          - estimated_fpr: float
          - drift_detected: bool
          - timestamp: str
          - recommendations: list[str]
    """
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if not fresh_legit_urls:
        return {
            "sample_size": 0,
            "flagged_count": 0,
            "estimated_fpr": 0.0,
            "drift_detected": False,
            "timestamp": now,
            "recommendations": ["No URLs provided for drift check."],
        }

    flagged = 0
    total = len(fresh_legit_urls)

    if detector is not None:
        for url in fresh_legit_urls:
            try:
                res = detector.analyze(url)
                if res.get("label") in ("phishing", "suspicious"):
                    flagged += 1
            except Exception as exc:
                logger.warning("Drift check failed for %s: %s", url, exc)

    estimated_fpr = flagged / total if total > 0 else 0.0
    drift_detected = estimated_fpr > max_acceptable_fpr

    recs: list[str] = []
    if drift_detected:
        recs.append(
            f"FPR ({estimated_fpr:.2%}) exceeds threshold ({max_acceptable_fpr:.2%}). "
            "Trigger automated retrain with recent hard negatives."
        )
    else:
        recs.append(f"Model stable. Estimated FPR on fresh legit URLs: {estimated_fpr:.2%}.")

    return {
        "sample_size": total,
        "flagged_count": flagged,
        "estimated_fpr": estimated_fpr,
        "drift_detected": drift_detected,
        "timestamp": now,
        "recommendations": recs,
    }


def report_feedback(
    url_hash: str,
    correct_label: str,
    feedback_notes: str | None = None,
    log_dir: str | Path | None = None,
) -> None:
    """
    Log user / analyst ground-truth feedback for false-positive / false-negative triage.

    In production: feeds the hard-negative mining loop (Phase 3 hard_negative.py).
    """
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    record = {
        "url_hash": url_hash,
        "correct_label": correct_label,
        "feedback_notes": feedback_notes,
        "timestamp": ts,
    }

    target_dir = Path(log_dir) if log_dir else _SHADOW_LOG_DIR
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        feedback_file = target_dir / "user_feedback.jsonl"
        with feedback_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception as exc:
        logger.warning("Failed to record feedback: %s", exc)

    logger.info("Feedback recorded for hash=%s correct_label=%s", url_hash, correct_label)
