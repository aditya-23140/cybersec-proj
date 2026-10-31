"""
preprocessing.py — Feature engineering and dataset splitting.

Applies ``feature_extractor.extract_features()`` to every URL in the dataset,
then produces stratified train / val / test splits with no URL overlap.

Network features (qty_nameservers, is_spf_domain, time_domain_activation)
are taken from pre-computed dataset columns when available; otherwise, the
fallback values defined in feature_extractor are used.
"""

from __future__ import annotations

import logging
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from .feature_extractor import FEATURE_NAMES, extract_features

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Feature extraction
# ─────────────────────────────────────────────────────────────────────────────


def _extract_row_features(
    url: str,
    precomputed: dict[str, Optional[float]],
) -> list[float]:
    """
    Extract features for a single URL.

    URL-computable features are always recomputed from the URL string for
    train/inference consistency. Network features use precomputed values when
    available, otherwise fall back to the module-level constants.

    Parameters
    ----------
    url:
        The raw URL string.
    precomputed:
        Dict mapping feature name → pre-computed value (or None if absent).
    """
    try:
        fv = extract_features(url, enable_dns=False)
    except ValueError as exc:
        logger.debug("Skipping invalid URL %r: %s", url, exc)
        return []

    features = fv.features.copy()

    # Override network features with dataset's pre-computed values if present
    net_idxs = {
        "qty_nameservers": FEATURE_NAMES.index("qty_nameservers"),
        "is_spf_domain": FEATURE_NAMES.index("is_spf_domain"),
        "time_domain_activation": FEATURE_NAMES.index("time_domain_activation"),
    }
    for feat, idx in net_idxs.items():
        val = precomputed.get(feat)
        if val is not None and not np.isnan(float(val)):
            features[idx] = float(val)

    return features


def extract_feature_matrix(
    df: pd.DataFrame,
    show_progress: bool = True,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Apply feature extraction to every row in *df*.

    Parameters
    ----------
    df:
        DataFrame with columns ``url``, ``label``, and optionally
        ``qty_nameservers``, ``is_spf_domain``, ``time_domain_activation``.
    show_progress:
        Log progress every 10 000 rows.

    Returns
    -------
    (X, y, valid_idx)
        ``X``         — float32 array of shape (n_valid, 8)
        ``y``         — int array of shape (n_valid,)
        ``valid_idx`` — original DataFrame indices of rows that were processed
                        successfully (for traceability).
    """
    # Determine which pre-computed columns are available
    available_net_cols = [
        c for c in ("qty_nameservers", "is_spf_domain", "time_domain_activation")
        if c in df.columns
    ]
    if available_net_cols:
        logger.info(
            "Using pre-computed network features from dataset columns: %s",
            available_net_cols,
        )
    else:
        logger.info(
            "No pre-computed network feature columns found — fallback values will be used."
        )

    X_rows: list[list[float]] = []
    y_rows: list[int] = []
    valid_indices: list[int] = []

    total = len(df)
    for i, (idx, row) in enumerate(df.iterrows()):
        if show_progress and i % 10_000 == 0:
            logger.info("Feature extraction: %d / %d rows", i, total)

        precomputed: dict[str, Optional[float]] = {}
        for col in available_net_cols:
            raw = row.get(col)
            precomputed[col] = float(raw) if raw is not None and not pd.isna(raw) else None

        features = _extract_row_features(str(row["url"]), precomputed)
        if not features:
            continue  # skip invalid URLs

        X_rows.append(features)
        y_rows.append(int(row["label"]))
        valid_indices.append(int(idx))

    if not X_rows:
        raise RuntimeError("No valid features could be extracted from the dataset.")

    X = np.array(X_rows, dtype=np.float32)
    y = np.array(y_rows, dtype=np.int64)
    valid_idx = np.array(valid_indices, dtype=np.int64)

    logger.info(
        "Feature extraction complete: %d / %d rows kept, shape=%s",
        len(X_rows),
        total,
        X.shape,
    )
    return X, y, valid_idx


# ─────────────────────────────────────────────────────────────────────────────
# Train / val / test splitting
# ─────────────────────────────────────────────────────────────────────────────


def stratified_split(
    X: np.ndarray,
    y: np.ndarray,
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_state: int = 42,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """
    Produce stratified train / val / test splits.

    Parameters
    ----------
    X, y:
        Feature matrix and labels.
    test_size:
        Fraction for the test set.
    val_size:
        Fraction for the validation set (of the *original* dataset).
    random_state:
        Random seed.

    Returns
    -------
    X_train, X_val, X_test, y_train, y_val, y_test
    """
    # Step 1: Split off test set
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=random_state
    )

    # Step 2: Split val from remaining
    val_fraction_of_temp = val_size / (1.0 - test_size)
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp,
        y_temp,
        test_size=val_fraction_of_temp,
        stratify=y_temp,
        random_state=random_state,
    )

    logger.info(
        "Split sizes — train: %d, val: %d, test: %d",
        len(X_train),
        len(X_val),
        len(X_test),
    )
    for name, ys in [("train", y_train), ("val", y_val), ("test", y_test)]:
        ph = int((ys == 1).sum())
        le = int((ys == 0).sum())
        logger.info("  %s — phishing: %d, legitimate: %d", name, ph, le)

    return X_train, X_val, X_test, y_train, y_val, y_test
