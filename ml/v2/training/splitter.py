"""
splitter.py — Time-based + domain-grouped train/val/test splitting.
"""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)


def time_domain_split(
    df: pd.DataFrame,
    *,
    time_col: str = "collected_at",
    domain_col: str = "registered_domain",
    train_frac: float = 0.70,
    val_frac: float = 0.15,
) -> tuple[pd.Index, pd.Index, pd.Index]:
    """
    Split *df* chronologically, then remove domain leakage.

    Algorithm:
    1. Sort by *time_col*.
    2. Split chronologically: train = first 70%, val = next 15%, test = last 15%.
    3. Remove domain leakage: any domain in val or test that is also in train,
       or any domain overlapping between val and test, is assigned entirely to test.
    4. Return (train_idx, val_idx, test_idx) preserving time order within splits.
    """
    if df.empty:
        empty = pd.Index([], dtype=df.index.dtype)
        return empty, empty, empty

    df_sorted = df.sort_values(time_col, kind="mergesort")
    n = len(df_sorted)

    n_train = int(n * train_frac)
    n_val = int(n * val_frac)
    n_test = n - n_train - n_val

    if n_test < 0:
        raise ValueError(f"train_frac ({train_frac}) + val_frac ({val_frac}) > 1.0")

    idx_train_raw = df_sorted.index[:n_train]
    idx_val_raw = df_sorted.index[n_train : n_train + n_val]
    idx_test_raw = df_sorted.index[n_train + n_val :]

    train_domains = set(df.loc[idx_train_raw, domain_col].dropna().unique())
    val_domains = set(df.loc[idx_val_raw, domain_col].dropna().unique())
    test_domains = set(df.loc[idx_test_raw, domain_col].dropna().unique())

    # Leakage domains: any domain that spans across train and (val or test),
    # or across val and test.
    leaked_to_test = (train_domains & val_domains) | (train_domains & test_domains) | (val_domains & test_domains)

    # Any domain in leaked_to_test is moved entirely to test
    # (train and val keep only disjoint, pure domains)
    mask_train_keep = ~df.loc[idx_train_raw, domain_col].isin(leaked_to_test)
    idx_train_final = idx_train_raw[mask_train_keep]
    idx_train_moved = idx_train_raw[~mask_train_keep]

    mask_val_keep = ~df.loc[idx_val_raw, domain_col].isin(leaked_to_test)
    idx_val_final = idx_val_raw[mask_val_keep]
    idx_val_moved = idx_val_raw[~mask_val_keep]

    idx_test_all = idx_test_raw.union(idx_train_moved).union(idx_val_moved)
    idx_test_final = df_sorted.index[df_sorted.index.isin(idx_test_all)]

    logger.info(
        "time_domain_split: train=%d, val=%d, test=%d (total=%d, moved_domains=%d)",
        len(idx_train_final),
        len(idx_val_final),
        len(idx_test_final),
        n,
        len(leaked_to_test),
    )

    return idx_train_final, idx_val_final, idx_test_final


def leave_one_source_out_split(
    df: pd.DataFrame,
    held_out_source: str,
    *,
    source_col: str = "source",
    val_frac: float = 0.15,
    time_col: str = "collected_at",
    seed: int = 42,
) -> tuple[pd.Index, pd.Index, pd.Index]:
    """
    Leave-one-source-out split.

    - test: all rows where source == *held_out_source*
    - train + val: remaining rows, sorted chronologically and split
    """
    if source_col not in df.columns:
        raise ValueError(f"Column '{source_col}' not found in DataFrame")

    test_mask = df[source_col] == held_out_source
    idx_test = df.index[test_mask]
    idx_other = df.index[~test_mask]

    if idx_other.empty:
        empty = pd.Index([], dtype=df.index.dtype)
        return empty, empty, idx_test

    df_other = df.loc[idx_other]
    if time_col in df_other.columns:
        df_other = df_other.sort_values(time_col, kind="mergesort")

    n_other = len(df_other)
    n_val = int(n_other * val_frac)
    n_train = n_other - n_val

    idx_train = df_other.index[:n_train]
    idx_val = df_other.index[n_train:]

    return idx_train, idx_val, idx_test
