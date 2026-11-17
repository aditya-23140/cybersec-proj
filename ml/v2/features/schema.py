"""
schema.py — Loads and validates feature_schema_v2.json.

The schema JSON is expected at a path given by the caller.
If the schema is missing (Phase 1 not yet completed), a minimal built-in
fallback is used so other modules can still function.
"""

from __future__ import annotations

import json
import logging
import math
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Minimal built-in fallback schema
# Matches Phase 1 specification: missing_fill is -1.0 for missing / optional
# ---------------------------------------------------------------------------

_FALLBACK_FEATURES: list[dict[str, Any]] = [
    # Group 1 — URL lexical (24 features)
    {"name": "url_length",              "group": "url_lexical", "missing_fill": 0.0},
    {"name": "hostname_length",         "group": "url_lexical", "missing_fill": 0.0},
    {"name": "path_length",             "group": "url_lexical", "missing_fill": 0.0},
    {"name": "query_length",            "group": "url_lexical", "missing_fill": 0.0},
    {"name": "fragment_length",         "group": "url_lexical", "missing_fill": 0.0},
    {"name": "url_entropy",             "group": "url_lexical", "missing_fill": 0.0},
    {"name": "hostname_entropy",        "group": "url_lexical", "missing_fill": 0.0},
    {"name": "path_entropy",            "group": "url_lexical", "missing_fill": 0.0},
    {"name": "digit_ratio_url",         "group": "url_lexical", "missing_fill": 0.0},
    {"name": "letter_ratio_url",        "group": "url_lexical", "missing_fill": 0.0},
    {"name": "special_char_count_url",  "group": "url_lexical", "missing_fill": 0.0},
    {"name": "subdomain_depth",         "group": "url_lexical", "missing_fill": 0.0},
    {"name": "tld_risk_score",          "group": "url_lexical", "missing_fill": 0.0},
    {"name": "has_ip_host",             "group": "url_lexical", "missing_fill": 0.0},
    {"name": "has_userinfo",            "group": "url_lexical", "missing_fill": 0.0},
    {"name": "has_punycode",            "group": "url_lexical", "missing_fill": 0.0},
    {"name": "idn_homograph_score",     "group": "url_lexical", "missing_fill": 0.0},
    {"name": "shortener_flag",          "group": "url_lexical", "missing_fill": 0.0},
    {"name": "shared_hosting_flag",     "group": "url_lexical", "missing_fill": 0.0},
    {"name": "qty_dots_url",            "group": "url_lexical", "missing_fill": 0.0},
    {"name": "qty_hyphens_url",         "group": "url_lexical", "missing_fill": 0.0},
    {"name": "qty_at_url",              "group": "url_lexical", "missing_fill": 0.0},
    {"name": "path_token_count",        "group": "url_lexical", "missing_fill": 0.0},
    {"name": "path_depth",              "group": "url_lexical", "missing_fill": 0.0},
    # Group 2 — Brand (8 features)
    {"name": "brand_edit_distance_min",         "group": "brand", "missing_fill": 1.0},
    {"name": "brand_homoglyph_score",           "group": "brand", "missing_fill": 0.0},
    {"name": "brand_keyword_in_subdomain",      "group": "brand", "missing_fill": 0.0},
    {"name": "brand_keyword_in_path",           "group": "brand", "missing_fill": 0.0},
    {"name": "page_claimed_brand_mismatch",     "group": "brand", "missing_fill": -1.0},
    {"name": "known_brand_in_title",            "group": "brand", "missing_fill": -1.0},
    {"name": "known_brand_in_og",               "group": "brand", "missing_fill": -1.0},
    {"name": "registered_domain_matches_brand", "group": "brand", "missing_fill": 0.0},
    # Group 3 — Reputation (14 features)
    {"name": "domain_age_days",        "group": "reputation", "missing_fill": -1.0},
    {"name": "registrar_risk_score",   "group": "reputation", "missing_fill": -1.0},
    {"name": "mx_present",             "group": "reputation", "missing_fill": -1.0},
    {"name": "spf_present",            "group": "reputation", "missing_fill": -1.0},
    {"name": "dmarc_present",          "group": "reputation", "missing_fill": -1.0},
    {"name": "dns_ttl_min",            "group": "reputation", "missing_fill": -1.0},
    {"name": "a_record_count",         "group": "reputation", "missing_fill": -1.0},
    {"name": "tls_issuer_free_ca",     "group": "reputation", "missing_fill": -1.0},
    {"name": "tls_age_days",           "group": "reputation", "missing_fill": -1.0},
    {"name": "tls_validity_days",      "group": "reputation", "missing_fill": -1.0},
    {"name": "tls_san_count",          "group": "reputation", "missing_fill": -1.0},
    {"name": "tranco_rank_bucket",     "group": "reputation", "missing_fill": -1.0},
    {"name": "hosting_asn_risk",       "group": "reputation", "missing_fill": -1.0},
    {"name": "hosting_country_risk",   "group": "reputation", "missing_fill": -1.0},
    # Group 4 — Page content (16 features)
    {"name": "has_password_field",          "group": "page_content", "missing_fill": -1.0},
    {"name": "has_card_field",              "group": "page_content", "missing_fill": -1.0},
    {"name": "has_otp_field",               "group": "page_content", "missing_fill": -1.0},
    {"name": "form_action_cross_domain",    "group": "page_content", "missing_fill": -1.0},
    {"name": "null_action_form",            "group": "page_content", "missing_fill": -1.0},
    {"name": "external_script_ratio",       "group": "page_content", "missing_fill": -1.0},
    {"name": "external_css_ratio",          "group": "page_content", "missing_fill": -1.0},
    {"name": "hidden_iframe_count",         "group": "page_content", "missing_fill": -1.0},
    {"name": "js_obfuscation_score",        "group": "page_content", "missing_fill": -1.0},
    {"name": "right_click_disabled",        "group": "page_content", "missing_fill": -1.0},
    {"name": "meta_refresh_present",        "group": "page_content", "missing_fill": -1.0},
    {"name": "title_domain_overlap",        "group": "page_content", "missing_fill": -1.0},
    {"name": "urgency_keyword_score",       "group": "page_content", "missing_fill": -1.0},
    {"name": "text_to_html_ratio",          "group": "page_content", "missing_fill": -1.0},
    {"name": "login_form_on_unknown_domain","group": "page_content", "missing_fill": -1.0},
    {"name": "external_link_ratio",         "group": "page_content", "missing_fill": -1.0},
    # Group 5 — Redirect (5 features)
    {"name": "redirect_count",          "group": "redirect", "missing_fill": -1.0},
    {"name": "cross_domain_redirect",   "group": "redirect", "missing_fill": -1.0},
    {"name": "final_domain_changed",    "group": "redirect", "missing_fill": -1.0},
    {"name": "shortener_expanded",      "group": "redirect", "missing_fill": -1.0},
    {"name": "redirect_chain_length",   "group": "redirect", "missing_fill": -1.0},
]

_FALLBACK_SCHEMA: dict[str, Any] = {
    "version": "2.0.0-dev",
    "features": _FALLBACK_FEATURES,
}


class FeatureSchema:
    """Loaded and validated feature schema."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._raw: dict[str, Any] = {}
        self._features: list[dict[str, Any]] = []

        candidate_path = Path(path) if path is not None else Path("ml/v2/feature_schema_v2.json")
        if candidate_path.exists():
            try:
                with candidate_path.open("r", encoding="utf-8") as fh:
                    self._raw = json.load(fh)
                self._features = self._raw.get("features", [])
                logger.info("Loaded feature schema from %s (%d features)", candidate_path, len(self._features))
            except Exception as exc:
                logger.warning("Failed to load schema from %s: %s — using fallback", candidate_path, exc)
        elif path is not None:
            logger.warning("Schema file not found: %s — using fallback", candidate_path)

        if not self._features:
            logger.info("Using built-in fallback feature schema (%d features)", len(_FALLBACK_FEATURES))
            self._raw = _FALLBACK_SCHEMA
            self._features = list(_FALLBACK_FEATURES)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def version(self) -> str:
        return self._raw.get("version", self._raw.get("schema_version", "unknown"))

    @property
    def feature_names(self) -> list[str]:
        return [f["name"] for f in self._features]

    @property
    def feature_count(self) -> int:
        return len(self._features)

    def missing_fill(self, name: str) -> float:
        for f in self._features:
            if f["name"] == name:
                v = f.get("missing_fill", -1.0)
                if v is None or (isinstance(v, str) and v.lower() == "nan"):
                    return -1.0
                try:
                    return float(v)
                except (TypeError, ValueError):
                    return -1.0
        return -1.0

    def fill_map(self) -> dict[str, float]:
        """Returns {feature_name: missing_fill_value} for all features."""
        return {f["name"]: self.missing_fill(f["name"]) for f in self._features}

    def features_by_group(self, group: str) -> list[str]:
        # Normalize group names to handle variants like brand / brand_impersonation, redirect / redirect_behaviour
        aliases = {
            "brand": ["brand", "brand_impersonation"],
            "brand_impersonation": ["brand", "brand_impersonation"],
            "redirect": ["redirect", "redirect_behaviour"],
            "redirect_behaviour": ["redirect", "redirect_behaviour"],
            "url_lexical": ["url_lexical", "lexical"],
            "page_content": ["page_content", "content"],
            "reputation": ["reputation"],
        }
        match_groups = aliases.get(group, [group])
        return [f["name"] for f in self._features if f.get("group") in match_groups]

    def groups(self) -> list[str]:
        seen: list[str] = []
        for f in self._features:
            g = f.get("group", "")
            if g and g not in seen:
                seen.append(g)
        return seen
