"""
data_validation.py — Dataset quality checks before training.

Reports:
- Row count
- Duplicate URL count and percentage
- Label distribution and class balance ratio
- Missing value counts per column
- Sample URLs from each class
"""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────


def validate_dataset(df: pd.DataFrame, is_synthetic: bool = False) -> dict[str, Any]:
    """
    Validate *df* and return a summary report dictionary.

    Parameters
    ----------
    df:
        DataFrame with at minimum ``url`` and ``label`` columns.
    is_synthetic:
        Whether the dataset was synthetically generated (logged as a warning).

    Returns
    -------
    dict
        Validation report with keys: row_count, duplicate_count,
        duplicate_pct, label_distribution, class_balance_ratio,
        missing_values, is_synthetic.

    Raises
    ------
    ValueError
        If the dataset is empty or lacks required columns.
    """
    if df.empty:
        raise ValueError("Dataset is empty.")
    for col in ("url", "label"):
        if col not in df.columns:
            raise ValueError(f"Required column '{col}' missing from dataset.")

    report: dict[str, Any] = {}

    # Basic stats
    report["row_count"] = len(df)
    report["is_synthetic"] = is_synthetic

    # Duplicates (by URL)
    dup_mask = df["url"].duplicated(keep=False)
    report["duplicate_count"] = int(dup_mask.sum())
    report["duplicate_pct"] = round(
        report["duplicate_count"] / len(df) * 100, 2
    )

    # Label distribution
    value_counts = df["label"].value_counts().sort_index()
    report["label_distribution"] = value_counts.to_dict()

    n_phishing = int(value_counts.get(1, 0))
    n_legitimate = int(value_counts.get(0, 0))
    report["n_phishing"] = n_phishing
    report["n_legitimate"] = n_legitimate

    if n_legitimate > 0:
        report["class_balance_ratio"] = round(n_phishing / n_legitimate, 4)
    else:
        report["class_balance_ratio"] = float("inf")

    # Missing values
    report["missing_values"] = df.isnull().sum().to_dict()

    # Unique URLs
    report["unique_url_count"] = int(df["url"].nunique())

    # Log summary
    _print_report(report)

    return report


def _print_report(report: dict[str, Any]) -> None:
    sep = "=" * 60
    logger.info(sep)
    logger.info("DATASET VALIDATION REPORT")
    logger.info(sep)
    logger.info("  Synthetic dataset : %s", report["is_synthetic"])
    logger.info("  Total rows        : %d", report["row_count"])
    logger.info("  Unique URLs       : %d", report["unique_url_count"])
    logger.info(
        "  Duplicates        : %d (%.2f%%)",
        report["duplicate_count"],
        report["duplicate_pct"],
    )
    logger.info("  Label distribution:")
    for label, count in report["label_distribution"].items():
        name = "phishing" if label == 1 else "legitimate"
        logger.info("    %d (%s): %d rows", label, name, count)
    logger.info("  Class balance ratio (phishing/legit): %.4f", report["class_balance_ratio"])
    missing = {k: v for k, v in report["missing_values"].items() if v > 0}
    if missing:
        logger.warning("  Missing values: %s", missing)
    else:
        logger.info("  Missing values: none")
    logger.info(sep)


def deduplicate(df: pd.DataFrame) -> pd.DataFrame:
    """
    Remove duplicate URLs, keeping the first occurrence.
    Returns the de-duplicated DataFrame and logs how many rows were removed.
    """
    before = len(df)
    df = df.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    removed = before - len(df)
    if removed:
        logger.info("Removed %d duplicate URLs.", removed)
    return df
