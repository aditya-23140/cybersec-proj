"""
ml/v2/serving/detector.py — Main inference class for FihhGuard v2.

Layer order (spec-mandated):
  1. Threat-intel lookup  (always, before model)
  2. Top-10k allowlist    (exact registered domain only)
  3. Model               (FeatureExtractor + ModelBundle)

Returns dict with keys defined in Detector.analyze() docstring.
"""

from __future__ import annotations

import gzip
import logging
import pickle
import sys
import traceback
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Ensure local packages directory is accessible for joblib, xgboost, scikit-learn
_CANDIDATE_PKGS = [
    Path(__file__).resolve().parents[3] / ".pkgs",
]
for _pkg in _CANDIDATE_PKGS:
    if _pkg.exists() and str(_pkg) not in sys.path:
        sys.path.insert(0, str(_pkg))

# Shim dill in case unpickler references dill._dill._load_type from Kaggle environment
if "dill" not in sys.modules:
    import types as _types
    _dill = _types.ModuleType("dill")
    _dill_sub = _types.ModuleType("dill._dill")
    def _load_type(name: str):
        import builtins
        return getattr(builtins, name, getattr(_types, name, None))
    _dill_sub._load_type = _load_type
    _dill._dill = _dill_sub
    sys.modules["dill"] = _dill
    sys.modules["dill._dill"] = _dill_sub

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SHAP feature → human-readable template
# ---------------------------------------------------------------------------

FEATURE_REASON_TEMPLATES: dict[str, str] = {
    "url_length":               "URL is unusually long ({value:.0f} chars)",
    "hostname_length":          "Hostname is unusually long ({value:.0f} chars)",
    "path_length":              "URL path is unusually long ({value:.0f} chars)",
    "query_length":             "URL query string is unusually long ({value:.0f} chars)",
    "url_entropy":              "URL has high character randomness (entropy {value:.2f})",
    "hostname_entropy":         "Hostname has high character randomness (entropy {value:.2f})",
    "path_entropy":             "URL path has high character randomness (entropy {value:.2f})",
    "digit_ratio_url":          "URL contains a high proportion of digits ({value:.0%})",
    "letter_ratio_url":         "URL has a typical letter-to-symbol balance ({value:.0%})",
    "special_char_count_url":   "URL contains many special characters ({value:.0f})",
    "path_token_count":         "URL path contains multiple segments ({value:.0f})",
    "path_depth":               "URL path is deeply nested ({value:.0f} levels)",
    "subdomain_depth":          "URL has an unusual number of subdomains ({value:.0f})",
    "tld_risk_score":           "Top-level domain is associated with phishing ({value:.1f})",
    "has_ip_host":              "URL uses a raw IP address instead of a domain name",
    "has_userinfo":             "URL embeds credentials (@ in netloc), a common deception",
    "has_punycode":             "Hostname uses Punycode encoding, possible IDN homograph attack",
    "idn_homograph_score":      "Hostname contains look-alike Unicode characters ({value:.2f})",
    "shortener_flag":           "URL uses a known link-shortening service",
    "shared_hosting_flag":      "URL is hosted on a shared/free hosting platform",
    "qty_dots_url":             "URL contains an unusual number of dots ({value:.0f})",
    "qty_hyphens_url":          "URL contains an unusual number of hyphens ({value:.0f})",
    "brand_edit_distance_min":  "Domain closely resembles a known brand (edit distance {value:.0f})",
    "brand_homoglyph_score":    "Domain uses characters that visually mimic a brand ({value:.2f})",
    "brand_keyword_in_subdomain": "Brand keyword found in subdomain, possible impersonation",
    "brand_keyword_in_path":    "Brand keyword found in URL path, possible impersonation",
    "page_claimed_brand_mismatch": "Page claims to be a brand that does not match the domain",
    "domain_age_days":          "Domain was registered very recently ({value:.0f} days ago)",
    "registrar_risk_score":     "Domain registered with a high-risk registrar ({value:.2f})",
    "tls_issuer_free_ca":       "TLS certificate issued by a free CA (common for phishing)",
    "tls_age_days":             "TLS certificate was issued very recently ({value:.0f} days ago)",
    "tranco_rank_bucket":       "Domain has low web traffic rank",
    "has_password_field":       "Page contains a password input field",
    "has_card_field":           "Page contains a credit card input field",
    "has_otp_field":            "Page requests a one-time verification code (OTP/2FA)",
    "form_action_cross_domain": "Form submits credentials to a different website",
    "null_action_form":         "Form has no submission target (data harvesting pattern)",
    "external_script_ratio":    "Page loads scripts from external domains ({value:.0%})",
    "external_css_ratio":       "Page styling references external third-party sources",
    "external_link_ratio":      "Page links predominantly lead outside the website ({value:.0%})",
    "hidden_iframe_count":      "Page embeds hidden iframes ({value:.0f})",
    "js_obfuscation_score":     "JavaScript on the page appears obfuscated ({value:.2f})",
    "right_click_disabled":     "Right-click is disabled to prevent security inspection",
    "meta_refresh_present":     "Page forces an immediate silent meta-refresh redirect",
    "title_domain_overlap":     "Page title has little relation to domain identity",
    "urgency_keyword_score":    "Page contains deceptive urgency or threat language",
    "text_to_html_ratio":       "Low text-to-code ratio, typical of cloned phishing templates",
    "login_form_on_unknown_domain": "Credential login form found on an unverified domain",
    "redirect_count":           "URL redirects multiple times ({value:.0f} hops)",
    "cross_domain_redirect":    "Redirect crosses to a different domain",
    "final_domain_changed":     "Redirect chain ends on an entirely different domain",
    "shortener_expanded":       "URL was behind a shortener that expanded to this destination",
    "redirect_chain_length":    "Redirect chain traverses {value:.0f} intermediary hops",
}

_DEFAULT_TEMPLATE = "Feature '{name}' has an anomalous value ({value:.4g})"


def _feature_reason(name: str, value: float, contrib: float = 0.0) -> str:
    if name == "brand_edit_distance_min":
        if value == 0.0:
            return "Domain exactly matches an official brand domain"
        elif value <= 2.0:
            return f"Domain closely resembles a known brand (edit distance {value:.0f})"
        else:
            return "Domain does not mimic known popular brands"

    if name in ("exact_brand", "registered_domain_matches_brand"):
        if value > 0:
            return "Registered domain matches a recognized brand domain"
        return "Domain is independent of recognized brand registries"

    if name in ("url_length", "hostname_length", "path_length", "query_length"):
        part = name.replace("_length", "").capitalize()
        if value > 65:
            return f"{part} is unusually long ({value:.0f} chars)"
        elif value == 0:
            return f"URL has no {part.lower()} component"
        else:
            return f"{part} length is standard ({value:.0f} chars)"

    if name == "subdomain_depth":
        if value > 1:
            return f"URL has {value:.0f} nested subdomains"
        return "Standard domain structure with no suspicious subdomain nesting"

    if name == "tld_risk_score":
        if value >= 0.5:
            return "Top-level domain has high historical correlation with phishing"
        return "Standard and reputable top-level domain"

    if name in ("qty_hyphens_url", "qty_dots_url"):
        char_type = name.split("_")[1]
        if value >= 3:
            return f"URL contains multiple {char_type} ({value:.0f})"
        return f"Normal count of {char_type} ({value:.0f})"

    tmpl = FEATURE_REASON_TEMPLATES.get(name, _DEFAULT_TEMPLATE)
    try:
        return tmpl.format(name=name, value=value)
    except Exception:
        return f"{name.replace('_', ' ')}: {value:.3g}"


# ---------------------------------------------------------------------------
# Registered-domain helper (no external deps)
# ---------------------------------------------------------------------------

def _registered_domain(hostname: str) -> str:
    """Return eTLD+1 for hostname (best-effort, no tldextract)."""
    if not hostname:
        return ""
    labels = hostname.lower().split(".")
    if len(labels) < 2:
        return hostname.lower()
    return ".".join(labels[-2:])


# ---------------------------------------------------------------------------
# ModelBundle loader
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "2.0.0-dev"


def _load_bundle(path: str) -> dict[str, Any]:
    """
    Load a bundle from a .pkl or .pkl.gz file.
    Supports joblib (compressed and plain) and pickle serialization formats.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Bundle not found: {path}")

    data: Any = None

    # 1. Try joblib with gzip decompression handle
    try:
        import joblib
        if str(path).endswith(".gz"):
            with gzip.open(p, "rb") as fh:
                data = joblib.load(fh)
        else:
            data = joblib.load(p)
    except Exception as exc1:
        logger.debug("joblib.load(fh) failed: %s", exc1)

    # 2. Try direct joblib.load(path)
    if data is None:
        try:
            import joblib
            data = joblib.load(str(p))
        except Exception as exc2:
            logger.debug("joblib.load(path) failed: %s", exc2)

    # 3. Try standard pickle
    if data is None:
        try:
            opener = gzip.open if str(path).endswith(".gz") else open
            with opener(p, "rb") as fh:
                data = pickle.load(fh)
        except Exception as exc3:
            logger.debug("pickle.load failed: %s", exc3)

    if data is None:
        raise ValueError(f"Could not deserialize bundle at {path} using joblib or pickle")

    if hasattr(data, "__dict__") and not isinstance(data, dict):
        bundle = {
            "model": getattr(data, "model", None),
            "calibrator": getattr(data, "calibrator", None),
            "schema_version": getattr(data, "schema_version", "2.0.0-dev"),
            "model_version": getattr(data, "model_version", "2.0.0"),
            "training_cutoff": getattr(data, "training_cutoff", ""),
            "data_card_version": getattr(data, "data_card_version", "v2.0"),
            "t_phishing": getattr(data, "t_phishing", 0.7),
            "t_suspicious": getattr(data, "t_suspicious", 0.4),
            "thresholds": {
                "phishing": getattr(data, "t_phishing", 0.7),
                "suspicious": getattr(data, "t_suspicious", 0.4),
            },
            "feature_names": getattr(data, "features", []),
            "features": getattr(data, "features", []),
            "metrics": getattr(data, "metrics", {}),
            "content_feature_groups": ["page_content"],
        }
    else:
        bundle = dict(data)
        if "thresholds" not in bundle:
            bundle["thresholds"] = {
                "phishing": bundle.get("t_phishing", 0.7),
                "suspicious": bundle.get("t_suspicious", 0.4),
            }
        if "feature_names" not in bundle and "features" in bundle:
            bundle["feature_names"] = bundle["features"]
        if "content_feature_groups" not in bundle:
            bundle["content_feature_groups"] = ["page_content"]

    # Verify schema major version matches
    sv = str(bundle.get("schema_version", ""))
    if not sv.startswith("2"):
        raise ValueError(
            f"Bundle schema_version={sv!r} but Detector requires major version 2. "
            "Retrain the model with Phase 3."
        )
    return bundle


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class Detector:
    """
    Main inference engine for FihhGuard v2.

    Layer order (enforced in analyze):
      1. Threat-intel lookup  (always, before model)
      2. Top-10k allowlist    (exact registered domain only)
      3. Model               (FeatureExtractor + ModelBundle)

    Returns dict with keys:
      label: 'phishing' | 'suspicious' | 'safe'
      score: float [0,1]  (calibrated)
      mode: 'url-only' | 'url+reputation' | 'url+content' | 'full'
      decided_by: 'threat_intel' | 'allowlist' | 'model'
      groups_missing: list[str]
      top_features: list[dict]
      model_version: str
      schema_version: str
      training_cutoff: str
      fetch_error: str | None
      content_ignored: bool
    """

    def __init__(
        self,
        bundle_path: str,
        tranco_top10k: set[str] | None = None,
    ) -> None:
        """Load bundle. Raises ValueError if schema version mismatches."""
        self._bundle_path = bundle_path
        self._bundle: dict[str, Any] | None = None
        self._tranco_top10k: set[str] = tranco_top10k or set()
        self._loaded = False
        self._load_error: str | None = None

        try:
            self._bundle = _load_bundle(bundle_path)
            self._loaded = True
            logger.info(
                "Detector loaded bundle: version=%s schema=%s cutoff=%s",
                self._bundle.get("model_version", "?"),
                self._bundle.get("schema_version", "?"),
                self._bundle.get("training_cutoff", "?"),
            )
        except Exception as exc:
            self._load_error = str(exc)
            logger.error("Detector failed to load bundle: %s", exc)
            raise

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def model_version(self) -> str:
        if self._bundle:
            return str(self._bundle.get("model_version", "unknown"))
        return "unknown"

    @property
    def schema_version(self) -> str:
        if self._bundle:
            return str(self._bundle.get("schema_version", SCHEMA_VERSION))
        return SCHEMA_VERSION

    @property
    def training_cutoff(self) -> str:
        if self._bundle:
            return str(self._bundle.get("training_cutoff", "unknown"))
        return "unknown"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_features(
        self,
        url: str,
        *,
        html: str | None,
        whois_data: dict | None,
        dns_data: dict | None,
        tls_data: dict | None,
        tranco_rank: int | None,
        redirect_history: list[str] | None,
        final_url: str | None,
    ) -> tuple[list[float], str, list[str]]:
        """
        Run FeatureExtractor and return (feature_vector, mode, groups_missing).
        """
        groups_missing: list[str] = []

        if html is None:
            groups_missing.append("page_content: html not provided")
        if all(x is None for x in (whois_data, dns_data, tls_data, tranco_rank)):
            groups_missing.append("reputation: WHOIS/DNS/TLS lookup not provided")
        if redirect_history is None and final_url is None:
            groups_missing.append("redirect: redirect history not provided")

        try:
            sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
            from ml.v2.features import FeatureExtractor  # type: ignore[import]

            extractor = FeatureExtractor()
            feat_arr = extractor.extract_as_array(
                url,
                html=html,
                whois_data=whois_data,
                dns_data=dns_data,
                tls_data=tls_data,
                tranco_rank=tranco_rank,
                redirect_history=redirect_history,
                final_url=final_url,
            )
            mode = extractor.get_mode(
                html=html,
                whois_data=whois_data,
                dns_data=dns_data,
                tls_data=tls_data,
                tranco_rank=tranco_rank,
            )
            return list(feat_arr), mode, groups_missing

        except Exception as exc:
            logger.warning("FeatureExtractor failed: %s, falling back to url_lexical only", exc)

        # Fallback: url_lexical only
        from ml.v2.features.url_lexical import extract_url_lexical

        lex = extract_url_lexical(url)
        bundle_feature_names: list[str] = self._bundle.get("feature_names", []) if self._bundle else []

        if bundle_feature_names:
            feat_vec = [lex.get(n, float("nan")) for n in bundle_feature_names]
        else:
            feat_vec = list(lex.values())

        return feat_vec, "url-only", groups_missing

    def _run_model(self, feature_vector: list[float]) -> float:
        """Run model + calibration. Returns calibrated probability."""
        assert self._bundle is not None
        model = self._bundle["model"]
        calibrator = self._bundle.get("calibrator")

        import numpy as np

        X = np.array(feature_vector, dtype=float).reshape(1, -1)

        if hasattr(model, "predict_proba"):
            raw_prob: float = float(model.predict_proba(X)[0, 1])
        elif hasattr(model, "decision_function"):
            scores = model.decision_function(X)
            raw_prob = float(1.0 / (1.0 + np.exp(-scores)))
        else:
            raw_prob = float(model.predict(X)[0])

        if calibrator is not None:
            try:
                if hasattr(calibrator, "predict"):
                    calibrated = float(calibrator.predict(np.array([raw_prob]))[0])
                    return max(0.0, min(1.0, calibrated))
            except Exception as exc:
                logger.debug("Calibrator failed: %s — using raw prob", exc)

        return max(0.0, min(1.0, raw_prob))

    def _apply_thresholds(self, score: float) -> str:
        """Return 'phishing' | 'suspicious' | 'safe' based on bundle thresholds."""
        assert self._bundle is not None
        thresholds: dict[str, float] = self._bundle.get(
            "thresholds", {"phishing": 0.7, "suspicious": 0.4}
        )
        t_phishing = thresholds.get("phishing", 0.7)
        t_suspicious = thresholds.get("suspicious", 0.4)
        if score >= t_phishing:
            return "phishing"
        if score >= t_suspicious:
            return "suspicious"
        return "safe"

    def _compute_shap_top5(
        self, feature_vector: list[float]
    ) -> list[dict[str, Any]]:
        """
        Compute top contributing features.
        """
        if not self._bundle:
            return []

        model = self._bundle.get("model")
        feature_names: list[str] = self._bundle.get("feature_names", [])
        if not feature_names:
            try:
                from ml.v2.features.schema import FeatureSchema
                feature_names = FeatureSchema().feature_names
            except Exception:
                feature_names = [f"feat_{i}" for i in range(len(feature_vector))]

        import numpy as np

        X = np.array(feature_vector, dtype=float).reshape(1, -1)
        contributions: list[float] | None = None

        # 1) XGBoost native pred_contribs
        try:
            import xgboost as xgb
            if hasattr(model, "get_booster"):
                dmat = xgb.DMatrix(X, feature_names=feature_names[:X.shape[1]])
                contribs = model.get_booster().predict(dmat, pred_contribs=True)
                contributions = list(contribs[0, :-1])
        except Exception:
            pass

        # 2) Feature importances fallback
        if contributions is None and hasattr(model, "feature_importances_"):
            try:
                imps = model.feature_importances_
                contributions = [float(imp * val) for imp, val in zip(imps, feature_vector)]
            except Exception:
                pass

        if contributions is None or len(contributions) == 0:
            return []

        effective_names = feature_names if len(feature_names) == len(contributions) else [f"f{i}" for i in range(len(contributions))]
        pairs = list(zip(effective_names, feature_vector, contributions))
        pairs.sort(key=lambda t: abs(t[2]), reverse=True)
        top5 = pairs[:5]

        result = []
        for name, value, contrib in top5:
            result.append(
                {
                    "name": name,
                    "feature": name,
                    "value": float(value) if not _is_nan(value) else None,
                    "contribution": float(contrib),
                    "reason": _feature_reason(name, float(value) if not _is_nan(value) else 0.0),
                }
            )
        return result

    # ------------------------------------------------------------------
    # Public inference API
    # ------------------------------------------------------------------

    def analyze(
        self,
        url: str,
        *,
        html: str | None = None,
        whois_data: dict | None = None,
        dns_data: dict | None = None,
        tls_data: dict | None = None,
        tranco_rank: int | None = None,
        redirect_history: list[str] | None = None,
        final_url: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Run full analysis. Never raises; returns error dict on failure.
        """
        _error_base = {
            "label": "safe",
            "score": 0.0,
            "mode": "url-only",
            "decided_by": "model",
            "groups_missing": [],
            "top_features": [],
            "model_version": self.model_version,
            "schema_version": self.schema_version,
            "training_cutoff": self.training_cutoff,
            "fetch_error": None,
            "content_ignored": False,
        }

        if not self._loaded or self._bundle is None:
            return {**_error_base, "fetch_error": f"model not loaded: {self._load_error}"}

        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()
            reg_domain = _registered_domain(hostname)

            # ----------------------------------------------------------------
            # Pure Model Inference: verdicts are determined strictly by the ML model
            # ----------------------------------------------------------------
            feature_vector, mode, groups_missing = self._extract_features(
                url,
                html=html,
                whois_data=whois_data,
                dns_data=dns_data,
                tls_data=tls_data,
                tranco_rank=tranco_rank,
                redirect_history=redirect_history,
                final_url=final_url,
            )

            score = self._run_model(feature_vector)
            label = self._apply_thresholds(score)
            top_features = self._compute_shap_top5(feature_vector)

            content_feature_groups: list[str] = self._bundle.get(
                "content_feature_groups", ["page_content"]
            )
            trained_with_content = bool(content_feature_groups)
            content_ignored = html is not None and not trained_with_content

            return {
                "label": label,
                "score": score,
                "mode": mode,
                "decided_by": "model",
                "groups_missing": groups_missing,
                "top_features": top_features,
                "model_version": self.model_version,
                "schema_version": self.schema_version,
                "training_cutoff": self.training_cutoff,
                "fetch_error": None,
                "content_ignored": content_ignored,
            }

        except Exception as exc:
            tb = traceback.format_exc()
            logger.error("Detector.analyze raised unexpectedly: %s\n%s", exc, tb)
            return {
                **_error_base,
                "fetch_error": f"internal error: {exc}",
            }


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _is_nan(v: Any) -> bool:
    try:
        import math
        return math.isnan(float(v))
    except Exception:
        return False
