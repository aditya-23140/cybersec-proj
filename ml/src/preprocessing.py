"""
preprocessing.py — Feature engineering and dataset splitting.

Applies ``feature_extractor.extract_features()`` to every URL in the dataset,
then produces stratified or domain-disjoint train / val / test splits with no URL overlap.
"""

from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from .feature_extractor import FEATURE_NAMES, extract_features, get_tld_extract

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Feature extraction
# ─────────────────────────────────────────────────────────────────────────────


def _extract_row_features(url: str) -> list[float]:
    """
    Extract features for a single URL using the shared feature extractor.
    Guarantees 100% parity between training and inference.
    """
    try:
        fv = extract_features(url, enable_dns=False)
        return fv.features
    except ValueError as exc:
        logger.debug("Skipping invalid URL %r: %s", url, exc)
        return []


def extract_feature_matrix(
    df: pd.DataFrame,
    show_progress: bool = True,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Apply feature extraction to every row in *df*.

    Parameters
    ----------
    df:
        DataFrame with columns ``url`` and ``label``.
    show_progress:
        Log progress every 25 000 rows.

    Returns
    -------
    (X, y, valid_idx)
        ``X``         — float32 array of shape (n_valid, len(FEATURE_NAMES))
        ``y``         — int array of shape (n_valid,)
        ``valid_idx`` — original DataFrame indices of rows that were processed
                        successfully (for traceability).
    """
    X_rows: list[list[float]] = []
    y_rows: list[int] = []
    valid_indices: list[int] = []

    total = len(df)
    for i, (idx, row) in enumerate(df.iterrows()):
        if show_progress and i > 0 and i % 25_000 == 0:
            logger.info("Feature extraction: %d / %d rows", i, total)

        features = _extract_row_features(str(row["url"]))
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
    """
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=random_state
    )

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


def domain_grouped_split(
    X: np.ndarray,
    y: np.ndarray,
    urls: list[str] | np.ndarray,
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_state: int = 42,
) -> tuple[
    np.ndarray, np.ndarray, np.ndarray,
    np.ndarray, np.ndarray, np.ndarray,
    np.ndarray, np.ndarray, np.ndarray,
]:
    """Split by registrable domain to prevent domain leakage across splits."""
    ext_func = get_tld_extract()
    urls_arr = np.asarray(urls)

    groups = []
    for raw_url in urls_arr:
        host = (urlparse(str(raw_url)).hostname or "").lower().rstrip(".")
        extracted = ext_func(host)
        groups.append(
            f"{extracted.domain}.{extracted.suffix}"
            if extracted.domain and extracted.suffix
            else host
        )
    groups_array = np.asarray(groups)

    test_splitter = GroupShuffleSplit(
        n_splits=1, test_size=test_size, random_state=random_state
    )
    train_val_idx, test_idx = next(test_splitter.split(X, y, groups_array))
    val_fraction = val_size / (1.0 - test_size)
    val_splitter = GroupShuffleSplit(
        n_splits=1, test_size=val_fraction, random_state=random_state
    )
    train_rel, val_rel = next(
        val_splitter.split(
            X[train_val_idx], y[train_val_idx], groups_array[train_val_idx]
        )
    )
    train_idx = train_val_idx[train_rel]
    val_idx = train_val_idx[val_rel]

    logger.info(
        "Domain-grouped split sizes — train: %d, val: %d, test: %d; unique domains: %d",
        len(train_idx),
        len(val_idx),
        len(test_idx),
        len(set(groups_array)),
    )
    return (
        X[train_idx], X[val_idx], X[test_idx],
        y[train_idx], y[val_idx], y[test_idx],
        urls_arr[train_idx], urls_arr[val_idx], urls_arr[test_idx],
    )
