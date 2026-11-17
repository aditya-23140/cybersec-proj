"""
dataset.py — PhishDataset: loads parquet files, extracts features, handles dropout.
"""

from __future__ import annotations

import logging
import math
import random
from pathlib import Path
from typing import Any, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Fallback feature names if schema/extractor not fully loaded
_DEFAULT_GROUPS = {
    "url_lexical": [
        "url_length", "hostname_length", "path_length", "query_length",
        "fragment_length", "url_entropy", "hostname_entropy", "path_entropy",
        "digit_ratio_url", "letter_ratio_url", "special_char_count_url",
        "subdomain_depth", "tld_risk_score", "has_ip_host", "has_userinfo",
        "has_punycode", "idn_homograph_score", "shortener_flag",
        "shared_hosting_flag", "qty_dots_url", "qty_hyphens_url",
        "qty_at_url", "path_token_count", "path_depth",
    ],
    "brand": [
        "brand_edit_distance_min", "brand_homoglyph_score",
        "brand_keyword_in_subdomain", "brand_keyword_in_path",
        "page_claimed_brand_mismatch", "known_brand_in_title",
        "known_brand_in_og", "registered_domain_matches_brand",
    ],
    "reputation": [
        "domain_age_days", "registrar_risk_score", "mx_present", "spf_present",
        "dmarc_present", "dns_ttl_min", "a_record_count", "tls_issuer_free_ca",
        "tls_age_days", "tls_validity_days", "tls_san_count",
        "tranco_rank_bucket", "hosting_asn_risk", "hosting_country_risk",
    ],
    "page_content": [
        "has_password_field", "has_card_field", "has_otp_field",
        "form_action_cross_domain", "null_action_form", "external_script_ratio",
        "external_css_ratio", "hidden_iframe_count", "js_obfuscation_score",
        "right_click_disabled", "meta_refresh_present", "title_domain_overlap",
        "urgency_keyword_score", "text_to_html_ratio",
        "login_form_on_unknown_domain", "external_link_ratio",
    ],
    "redirect": [
        "redirect_count", "cross_domain_redirect", "final_domain_changed",
        "shortener_expanded", "redirect_chain_length",
    ],
}

_ALL_DEFAULT_FEATURES: list[str] = []
for _g_feats in _DEFAULT_GROUPS.values():
    _ALL_DEFAULT_FEATURES.extend(_g_feats)


class _MockExtractor:
    """Mock extractor for unit tests or fallback when FeatureExtractor is absent."""

    def __init__(self, schema_path: Any = None) -> None:
        self.feature_names = list(_ALL_DEFAULT_FEATURES)
        self.feature_count = len(self.feature_names)
        self._schema_version = "2.0.0-dev"

    @property
    def version(self) -> str:
        return self._schema_version

    def extract_as_array(self, url: str = "", **kwargs: Any) -> np.ndarray:
        if isinstance(url, dict):
            kwargs = url
            url = kwargs.get("url", "")
        arr = np.zeros(self.feature_count, dtype=np.float32)
        if url:
            arr[0] = float(len(str(url)))
        return arr

    def groups(self) -> list[str]:
        return list(_DEFAULT_GROUPS.keys())

    def group_indices(self, group: str) -> list[int]:
        g_feats = _DEFAULT_GROUPS.get(group, [])
        return [self.feature_names.index(f) for f in g_feats if f in self.feature_names]


def _build_extractor(extractor_or_path: Any) -> Any:
    if extractor_or_path is not None and not isinstance(extractor_or_path, (str, Path)):
        return extractor_or_path

    schema_path = str(extractor_or_path) if extractor_or_path else None
    try:
        from ml.v2.features.extractor import FeatureExtractor
        return FeatureExtractor(schema_path=schema_path)
    except Exception as exc:
        logger.warning("FeatureExtractor unavailable (%s); using MockExtractor", exc)
        return _MockExtractor(schema_path)


class PhishDataset:
    """
    Dataset loader for phishing classification.

    Parameters
    ----------
    parquet_paths : list of paths to parquet files.
    extractor : FeatureExtractor instance or schema path or None.
    label_col : Column name containing target label (0 = legit, 1 = phishing).
    url_col : Column name for URL.
    """

    def __init__(
        self,
        parquet_paths: list[str],
        extractor: Any = None,
        *,
        label_col: str = "label",
        url_col: str = "url",
    ) -> None:
        self.parquet_paths = [str(p) for p in parquet_paths]
        self.extractor = _build_extractor(extractor)
        self.label_col = label_col
        self.url_col = url_col
        self._feature_names: list[str] = getattr(
            self.extractor, "feature_names", list(_ALL_DEFAULT_FEATURES)
        )
        if hasattr(self.extractor, "schema") and hasattr(self.extractor.schema, "feature_names"):
            self._feature_names = self.extractor.schema.feature_names

    @property
    def feature_names(self) -> list[str]:
        return self._feature_names

    def load(self) -> tuple[np.ndarray, np.ndarray, pd.DataFrame]:
        """
        Loads all parquet files, extracts features row-by-row, replaces NaNs,
        and returns (X, y, metadata_df).

        Rows where extraction fails are skipped with a warning.
        """
        frames: list[pd.DataFrame] = []
        for path_str in self.parquet_paths:
            p = Path(path_str)
            if not p.exists():
                logger.warning("Parquet file does not exist: %s", path_str)
                continue
            try:
                df_part = pd.read_parquet(p)
                frames.append(df_part)
            except Exception as exc:
                logger.warning("Failed to load parquet %s: %s", path_str, exc)

        if not frames:
            logger.warning("No data found in parquet paths: %s", self.parquet_paths)
            n_feat = len(self._feature_names)
            return (
                np.empty((0, n_feat), dtype=np.float32),
                np.empty((0,), dtype=np.int32),
                pd.DataFrame(),
            )

        combined_df = pd.concat(frames, ignore_index=True)

        rows_x: list[np.ndarray] = []
        survived_indices: list[int] = []
        available_groups_list: list[list[str]] = []

        for idx, row in combined_df.iterrows():
            row_dict = row.to_dict()
            url = str(row_dict.get(self.url_col, ""))
            try:
                # Try calling extract_as_array(url, **row_dict) or extract_as_array(row_dict)
                try:
                    feat_arr = self.extractor.extract_as_array(url, **row_dict)
                except TypeError:
                    feat_arr = self.extractor.extract_as_array(row_dict)

                if feat_arr is None:
                    raise ValueError("Extractor returned None")
                arr = np.asarray(feat_arr, dtype=np.float32)
                if arr.shape[0] != len(self._feature_names):
                    # Resize or pad if mismatch
                    padded = np.zeros(len(self._feature_names), dtype=np.float32)
                    m = min(len(padded), len(arr))
                    padded[:m] = arr[:m]
                    arr = padded

                rows_x.append(arr)
                survived_indices.append(idx)

                # Track available groups for this row
                groups_for_row: list[str] = ["url_lexical"]
                if row_dict.get("html") is not None:
                    groups_for_row.append("page_content")
                if any(row_dict.get(k) is not None for k in ("whois_data", "dns_data", "tls_data")):
                    groups_for_row.append("reputation")
                if row_dict.get("redirect_history") is not None:
                    groups_for_row.append("redirect")
                groups_for_row.append("brand")
                available_groups_list.append(groups_for_row)

            except Exception as exc:
                logger.warning("Extraction error at row %s (%s): %s", idx, url, exc)

        if not rows_x:
            n_feat = len(self._feature_names)
            return (
                np.empty((0, n_feat), dtype=np.float32),
                np.empty((0,), dtype=np.int32),
                pd.DataFrame(),
            )

        X = np.stack(rows_x, axis=0)
        meta_df = combined_df.iloc[survived_indices].copy().reset_index(drop=True)
        meta_df["available_groups"] = available_groups_list

        # Fill NaNs using schema missing_fill
        fill_map = self._get_fill_map()
        for j, col_name in enumerate(self._feature_names):
            fill_val = fill_map.get(col_name, 0.0)
            if math.isnan(fill_val):
                fill_val = 0.0
            col_data = X[:, j]
            nan_mask = np.isnan(col_data)
            if nan_mask.any():
                X[nan_mask, j] = fill_val

        # Extract labels
        if self.label_col in meta_df.columns:
            y = meta_df[self.label_col].fillna(0).astype(np.int32).to_numpy()
        else:
            y = np.zeros(len(meta_df), dtype=np.int32)

        return X, y, meta_df

    def apply_feature_group_dropout(
        self,
        X: np.ndarray,
        groups: Optional[list[str]] = None,
        drop_prob: float = 0.3,
        seed: Optional[int] = 42,
    ) -> np.ndarray:
        """
        Randomly zero-out entire feature groups during training (simulate missing modes).
        """
        if groups is None:
            # Default to dropping optional groups: page_content, reputation, redirect
            groups = ["page_content", "reputation", "redirect"]

        rng = np.random.RandomState(seed)
        X_dropped = X.copy()
        n_samples = X_dropped.shape[0]

        for group_name in groups:
            indices = self._get_group_indices(group_name)
            if not indices:
                continue
            # For each sample, drop with probability drop_prob
            drop_mask = rng.rand(n_samples) < drop_prob
            # Get row indices where drop_mask is True
            rows_to_drop = np.where(drop_mask)[0]
            if rows_to_drop.size > 0:
                # Use advanced indexing to set specified columns to zero for those rows
                X_dropped[np.ix_(rows_to_drop, indices)] = 0.0

        return X_dropped

    def _get_fill_map(self) -> dict[str, float]:
        if hasattr(self.extractor, "schema") and hasattr(self.extractor.schema, "fill_map"):
            return self.extractor.schema.fill_map()
        return {}

    def _get_group_indices(self, group: str) -> list[int]:
        if hasattr(self.extractor, "group_indices"):
            return self.extractor.group_indices(group)
        if hasattr(self.extractor, "schema") and hasattr(self.extractor.schema, "features_by_group"):
            g_feats = self.extractor.schema.features_by_group(group)
            return [self._feature_names.index(f) for f in g_feats if f in self._feature_names]
        g_feats = _DEFAULT_GROUPS.get(group, [])
        return [self._feature_names.index(f) for f in g_feats if f in self._feature_names]
