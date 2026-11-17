"""
hard_negative.py — Hard negative and hard positive mining for iterative model improvement.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

import numpy as np
import pandas as pd

from ml.v2.training.bundle import ModelBundle
from ml.v2.training.dataset import PhishDataset

logger = logging.getLogger(__name__)


def mine_hard_negatives(
    bundle_or_path: Any,
    dataset_parquets: list[str],
    schema_path: Optional[str] = None,
    *,
    output_parquet: Optional[str] = None,
    top_k: int = 100,
    fp_threshold: float = 0.50,  # legit samples scored >= fp_threshold
    fn_threshold: float = 0.50,  # phish samples scored < fn_threshold
) -> dict[str, Any]:
    """
    Identifies high-loss samples:
    - Hard Negatives: true legitimate URLs scored with high phishing probability.
    - Hard Positives: true phishing URLs scored with low phishing probability.

    Parameters
    ----------
    bundle_or_path : ModelBundle or path to bundle.pkl.gz.
    dataset_parquets : Paths to parquet files to mine from.
    schema_path : Path to feature schema.
    output_parquet : Path to save mined hard samples.
    top_k : Number of hard samples to retain per category.
    fp_threshold : Minimum score to consider a legitimate sample a hard negative.
    fn_threshold : Maximum score to consider a phishing sample a hard positive.

    Returns
    -------
    dict with counts, top samples, and output file path.
    """
    if isinstance(bundle_or_path, (str, Path)):
        bundle = ModelBundle.load(bundle_or_path)
    else:
        bundle = bundle_or_path

    ds = PhishDataset(dataset_parquets, extractor=schema_path)
    X, y, meta_df = ds.load()

    if len(y) == 0:
        return {"error": "Empty dataset", "total_scanned": 0}

    probs = bundle.predict_proba(X)
    meta_df = meta_df.copy()
    meta_df["predicted_score"] = probs
    meta_df["predicted_label"] = [bundle.predict_label(s) for s in probs]
    meta_df["error_magnitude"] = np.abs(meta_df["predicted_score"] - meta_df["label"])

    # 1. Hard Negatives (y == 0, high predicted score)
    hard_neg_mask = (meta_df["label"] == 0) & (meta_df["predicted_score"] >= fp_threshold)
    hard_negatives_df = (
        meta_df[hard_neg_mask]
        .sort_values("predicted_score", ascending=False)
        .head(top_k)
    )

    # 2. Hard Positives (y == 1, low predicted score)
    hard_pos_mask = (meta_df["label"] == 1) & (meta_df["predicted_score"] < fn_threshold)
    hard_positives_df = (
        meta_df[hard_pos_mask]
        .sort_values("predicted_score", ascending=True)
        .head(top_k)
    )

    # Combine mined samples
    mined_df = pd.concat([hard_negatives_df, hard_positives_df], ignore_index=True)

    if output_parquet:
        out_p = Path(output_parquet)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        # Drop complex objects like list of groups before saving parquet if needed
        cols_to_save = [c for c in mined_df.columns if c != "available_groups"]
        mined_df[cols_to_save].to_parquet(out_p, index=False)
        logger.info("Saved %d hard samples to %s", len(mined_df), out_p)

    return {
        "total_scanned": int(len(meta_df)),
        "hard_negatives_found": int(len(hard_negatives_df)),
        "hard_positives_found": int(len(hard_positives_df)),
        "top_hard_negatives": hard_negatives_df[["url", "predicted_score", "source"]].head(10).to_dict(orient="records") if "url" in hard_negatives_df else [],
        "top_hard_positives": hard_positives_df[["url", "predicted_score", "source"]].head(10).to_dict(orient="records") if "url" in hard_positives_df else [],
        "output_path": str(output_parquet) if output_parquet else None,
    }
