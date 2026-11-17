"""
extractor.py — FeatureExtractor class orchestrating all feature groups.
"""

from __future__ import annotations

import logging
import math
from pathlib import Path
from typing import Any

from .brand import extract_brand_features
from .page_content import extract_page_content_features
from .redirect import extract_redirect_features
from .reputation import extract_reputation_features
from .schema import FeatureSchema
from .url_lexical import extract_url_lexical

try:
    import numpy as np
except ImportError:
    np = None

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Orchestrates all feature extraction groups for FihhGuard v2.
    """

    def __init__(
        self,
        schema_path: str | Path | None = None,
        tranco_path: str | Path | None = None,
    ) -> None:
        self.schema = FeatureSchema(schema_path)
        self.tranco_domains: list[str] | None = None

        if tranco_path is not None:
            p = Path(tranco_path)
            if p.exists():
                try:
                    domains: list[str] = []
                    with p.open("r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                parts = line.split(",")
                                domains.append(parts[-1].strip().lower())
                    self.tranco_domains = domains
                    logger.info("Loaded %d Tranco domains from %s", len(domains), p)
                except Exception as exc:
                    logger.warning("Failed to load Tranco file %s: %s", p, exc)

    def get_mode(
        self,
        *,
        html: str | None = None,
        whois_data: dict | None = None,
        dns_data: dict | None = None,
        tls_data: dict | None = None,
        tranco_rank: int | None = None,
        asn_data: dict | None = None,
        **kwargs: Any,
    ) -> str:
        """
        Determines feature extraction mode based on available inputs.
        Returns: 'url-only', 'url+reputation', 'url+content', or 'full'.
        """
        reputation_present = any(
            x is not None
            for x in (whois_data, dns_data, tls_data, tranco_rank, asn_data)
        )
        content_present = html is not None

        if reputation_present and content_present:
            return "full"
        if reputation_present:
            return "url+reputation"
        if content_present:
            return "url+content"
        return "url-only"

    def extract(
        self,
        url: str,
        *,
        html: str | None = None,
        whois_data: dict | None = None,
        dns_data: dict | None = None,
        tls_data: dict | None = None,
        tranco_rank: int | None = None,
        asn_data: dict | None = None,
        redirect_history: list[str] | None = None,
        final_url: str | None = None,
        page_title: str | None = None,
        og_site_name: str | None = None,
        **kwargs: Any,
    ) -> dict[str, float]:
        """
        Extracts all features for a URL and replaces NaNs with schema missing_fill values.
        Never raises.
        """
        try:
            raw_features: dict[str, float] = {}

            # 1. URL lexical
            raw_features.update(extract_url_lexical(url))

            # 2. Brand
            raw_features.update(
                extract_brand_features(
                    url,
                    tranco_domains=self.tranco_domains,
                    page_title=page_title,
                    og_site_name=og_site_name,
                )
            )

            # 3. Reputation
            raw_features.update(
                extract_reputation_features(
                    url,
                    whois_data=whois_data,
                    dns_data=dns_data,
                    tls_data=tls_data,
                    tranco_rank=tranco_rank,
                    asn_data=asn_data,
                )
            )

            # 4. Content
            raw_features.update(extract_page_content_features(url, html=html))

            # 5. Redirect
            raw_features.update(
                extract_redirect_features(
                    url,
                    redirect_history=redirect_history,
                    final_url=final_url,
                )
            )

            # Map to schema and replace missing/NaN with missing_fill
            out: dict[str, float] = {}
            for name in self.schema.feature_names:
                val = raw_features.get(name)
                fill_val = self.schema.missing_fill(name)

                if val is None or (isinstance(val, float) and math.isnan(val)):
                    out[name] = fill_val
                else:
                    try:
                        out[name] = float(val)
                    except (ValueError, TypeError):
                        out[name] = fill_val

            return out

        except Exception as exc:
            logger.warning("FeatureExtractor.extract failed for %r: %s", url, exc)
            return self.schema.fill_map()

    def extract_as_array(self, url: str, **kwargs: Any) -> Any:
        """
        Returns feature values in schema-defined column order as a numpy array
        (or list if numpy is not installed).
        """
        feats = self.extract(url, **kwargs)
        row = [feats.get(name, self.schema.missing_fill(name)) for name in self.schema.feature_names]
        if np is not None:
            return np.array(row, dtype=np.float32)
        return row
