#!/usr/bin/env python3
"""
phishing_model.py - Robust XGBoost phishing-URL detector (train + predict).

Based on: Misiek & Hyla, "XGBoost-Based URL Phishing Detection Method With
Cross-Dataset Validation", IEEE Access 2026 - with deliberate changes to make the
model generalise to ANY URL, not just the training datasets.

KEY DIFFERENCES FROM THE PAPER (and why)
-----------------------------------------
1. Features are computed from the URL STRING ONLY (no WHOIS / DNS / SPF lookups).
   The paper's domain-age, nameserver and SPF features are slow, fail offline, and
   are dataset-specific (their own Table 5 shows SPF rate 0.35 vs 0.96 across sets).
   String-only features work identically at training and inference time.
2. The URL scheme (http/https) is REMOVED before feature extraction. The paper found
   HTTPS was a dataset artefact (+12.8% on PhiUSIIL, +0.04% on GramBeddings). Today
   most phishing uses HTTPS, so relying on it hurts real-world accuracy.
3. Train/val/test splits are GROUPED BY REGISTERED DOMAIN, so the same site never
   appears on both sides (prevents the inflated 97.8% single-dataset scores).
4. Per-domain sample cap + URL deduplication, so big domains cannot dominate.
5. Augmentation (optional, on by default): scheme/www/case/trailing-slash variants and
   host-only copies for both classes, so path-length style artefacts are not a shortcut.
6. Regularised XGBoost (shallow trees, min_child_weight, subsample, L1/L2, gamma),
   randomised search with GroupKFold, then early stopping on a separate validation set.
7. scale_pos_weight is computed from the data (paper hard-coded ~1.95).
8. Probabilities are CALIBRATED (isotonic) on a held-out calibration split, and
   thresholds are picked from a target false-positive rate, not hard-coded.
9. Leave-one-source-out evaluation when several datasets are supplied, to measure
   true cross-dataset generalisation.
10. Inference never raises: malformed input yields a result with an error flag.

USAGE
-----
  pip install xgboost scikit-learn pandas numpy joblib        # tldextract optional

  # Train. Each --data is: path[,url_col,label_col,positive_value]
  # positive_value = the label value meaning PHISHING. It is required for numeric
  # labels (e.g. PhiUSIIL uses 1 = legitimate, so pass 0 there). Text labels such as
  # phishing/malicious/benign/legitimate are auto-detected.
  python phishing_model.py train \
      --data custom.csv,url,label,1 \
      --data grambeddings.csv,url,label,1 \
      --data phiusiil.csv,URL,label,0 \
      --out phish_model.joblib

  # Predict
  python phishing_model.py predict --model phish_model.joblib "http://paypa1-login.example.tk/verify"

  # In your project
  from phishing_model import PhishingDetector
  det = PhishingDetector.load("phish_model.joblib")
  print(det.predict(["https://www.google.com", "login-secure-paypal.xyz/update"]))
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
import warnings
from collections import Counter
from urllib.parse import urlsplit, unquote

import joblib
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore", category=UserWarning)

FEATURE_VERSION = 1
SEED = 42

# --------------------------------------------------------------------------- #
# Feature extraction (string only, deterministic, no network)
# --------------------------------------------------------------------------- #
try:  # offline-safe: empty suffix_list_urls uses the snapshot bundled with the package
    import tldextract
    _TLDX = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
except Exception:  # pragma: no cover
    _TLDX = None

_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "or", "ne", "go"}

SUSPICIOUS_WORDS = [
    "login", "signin", "log-in", "sign-in", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "banking", "bank", "password", "passwd", "credential",
    "wallet", "billing", "invoice", "payment", "suspend", "unlock", "recover", "support",
    "helpdesk", "webscr", "authenticate", "validate", "alert", "limited", "free", "bonus",
    "gift", "prize", "claim", "refund", "expire", "urgent",
]

# brand token -> legitimate registered domains (extend freely for your own use case)
BRANDS = {
    "paypal": {"paypal.com", "paypal.me"},
    "google": {"google.com", "google.co.uk", "google.co.in", "goo.gl", "gstatic.com", "googleapis.com"},
    "gmail": {"gmail.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com", "msn.com"},
    "outlook": {"outlook.com", "live.com"},
    "office365": {"office.com", "microsoft.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com", "amazon.co.jp"},
    "facebook": {"facebook.com", "fb.com", "fb.me"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "twitter": {"twitter.com", "x.com", "t.co"},
    "dropbox": {"dropbox.com"},
    "github": {"github.com", "github.io"},
    "ebay": {"ebay.com", "ebay.co.uk"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "usps": {"usps.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "citibank": {"citi.com", "citibank.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk"},
    "sbi": {"sbi.co.in", "onlinesbi.com"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
    "paytm": {"paytm.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "spotify": {"spotify.com"},
    "adobe": {"adobe.com"},
    "docusign": {"docusign.com", "docusign.net"},
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "lnkd.in", "s.id", "v.gd",
}

RISKY_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "icu", "click", "link", "work", "support",
    "zip", "mov", "buzz", "rest", "monster", "cyou", "sbs", "cfd", "live", "online", "site",
    "shop", "club", "vip", "fit", "loan", "country", "stream", "download", "gdn", "men",
}

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_HEX_IP_RE = re.compile(r"^0x[0-9a-f]+$", re.I)
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")
_VOWELS = set("aeiou")

FEATURE_NAMES = [
    "url_len", "host_len", "path_len", "query_len", "reg_domain_len", "subdomain_len",
    "dots_url", "dots_host", "hyphens_host", "hyphens_path", "hyphens_reg_domain",
    "digits_url_ratio", "digits_host_ratio", "letters_url_ratio", "host_to_url_ratio",
    "subdomain_count", "path_depth", "n_query_params", "tld_len",
    "has_ip_host", "has_port", "has_at", "has_userinfo", "double_slash_in_path",
    "has_punycode", "has_non_ascii", "pct_encoded_count", "hex_ratio_url",
    "q_count", "eq_count", "amp_count", "underscore_count", "tilde_count", "hash_count",
    "entropy_url", "entropy_host", "entropy_path", "entropy_reg_domain",
    "max_token_len_host", "avg_token_len_host", "n_tokens_host", "n_tokens_path",
    "vowel_ratio_reg_domain", "max_consonant_run_reg_domain", "digit_letter_switches_host",
    "susp_word_count_host", "susp_word_count_path", "susp_word_count_total",
    "brand_in_subdomain_or_path", "brand_in_reg_domain_mismatch", "brand_mismatch_any",
    "is_shortener", "risky_tld", "tld_is_cc", "www_in_subdomain_not_first",
    "http_in_path_or_host", "path_has_file_ext_exe", "path_has_file_ext_web",
    "long_digit_run_host", "repeated_char_run_host",
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _split_host(host: str):
    """Return (subdomain, registered_domain_label, suffix, registered_domain)."""
    if _TLDX is not None:
        try:
            ext = _TLDX(host)
            if ext.suffix:
                reg = f"{ext.domain}.{ext.suffix}" if ext.domain else ext.suffix
                return ext.subdomain, ext.domain, ext.suffix, reg
        except Exception:
            pass
    labels = host.split(".")
    if len(labels) <= 1:
        return "", host, "", host
    suffix_n = 2 if (len(labels) >= 3 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2) else 1
    suffix = ".".join(labels[-suffix_n:])
    dom = labels[-suffix_n - 1] if len(labels) > suffix_n else ""
    sub = ".".join(labels[: -suffix_n - 1]) if len(labels) > suffix_n + 1 else ""
    return sub, dom, suffix, f"{dom}.{suffix}" if dom else suffix


def normalise_url(raw) -> tuple[str, str, str, str]:
    """Return (host, path, query, scheme_removed_url). Scheme is intentionally dropped."""
    s = str(raw).strip().strip("\"'<>")
    s = re.sub(r"[\s\x00-\x1f]", "", s)
    if not s:
        raise ValueError("empty url")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", s):
        s = "http://" + s.lstrip("/")
    try:
        p = urlsplit(s)
        netloc, path, query = p.netloc, p.path, p.query
    except ValueError:  # e.g. invalid IPv6 bracket
        rest = s.split("://", 1)[1]
        netloc, _, tail = rest.partition("/")
        path, _, query = ("/" + tail).partition("?")
    host = netloc.rsplit("@", 1)[-1]
    host = re.sub(r":\d+$", "", host).strip(".").lower()
    if not host:
        raise ValueError("no host")
    if "." not in host and not host.startswith("[") and host != "localhost":
        raise ValueError("host has no dot")
    if re.search(r"[\s<>\"'{}|\\^`]", host):
        raise ValueError("invalid host characters")
    return host, path, query, netloc + path + (("?" + query) if query else "")


def registered_domain(url) -> str:
    try:
        host = normalise_url(url)[0]
        return _split_host(host)[3] or host
    except Exception:
        return str(url)[:64]


def extract_features(raw) -> list[float]:
    """Numeric feature vector in FEATURE_NAMES order. NaNs on unparseable input."""
    try:
        host, path, query, core = normalise_url(raw)
        netloc_raw = core.split("/", 1)[0].split("?", 1)[0]
        sub, dom, suffix, reg = _split_host(host)
        path_l = unquote(path).lower()
        full = (host + path + (("?" + query) if query else ""))
        full_l = full.lower()
        n = max(len(full), 1)

        is_ip = bool(_IP_RE.match(host) or _HEX_IP_RE.match(host) or host.startswith("["))
        host_tokens = [t for t in _TOKEN_SPLIT.split(host) if t]
        path_tokens = [t for t in _TOKEN_SPLIT.split(path_l) if t]
        dom_letters = [c for c in dom if c.isalpha()]

        # consonant run in registered-domain label
        run = best = 0
        for c in dom:
            if c.isalpha() and c not in _VOWELS:
                run += 1
                best = max(best, run)
            else:
                run = 0

        switches = sum(
            1 for a, b in zip(host, host[1:]) if (a.isdigit() and b.isalpha()) or (a.isalpha() and b.isdigit())
        )

        sw_host = sum(host.count(w) for w in SUSPICIOUS_WORDS)
        sw_path = sum((path_l + "?" + query.lower()).count(w) for w in SUSPICIOUS_WORDS)

        # brand logic: brand string appears somewhere it should not
        b_sub_path = b_dom_mis = 0
        outside = (sub + "/" + path_l + "/" + query.lower())
        for brand, legit in BRANDS.items():
            if reg in legit:
                continue
            if brand in outside:
                b_sub_path = 1
            if brand in dom:
                b_dom_mis = 1
        brand_any = int(b_sub_path or b_dom_mis)

        tld = suffix.split(".")[-1] if suffix else ""
        exe_ext = int(bool(re.search(r"\.(exe|scr|apk|bat|msi|zip|rar|jar|js|vbs|cmd|dmg)(\?|$)", path_l)))
        web_ext = int(bool(re.search(r"\.(php|asp|aspx|jsp|cgi|html?)(\?|$)", path_l)))
        sub_labels = [l for l in sub.split(".") if l]

        vals = {
            "url_len": len(full), "host_len": len(host), "path_len": len(path), "query_len": len(query),
            "reg_domain_len": len(reg), "subdomain_len": len(sub),
            "dots_url": full.count("."), "dots_host": host.count("."),
            "hyphens_host": host.count("-"), "hyphens_path": path.count("-"),
            "hyphens_reg_domain": reg.count("-"),
            "digits_url_ratio": sum(c.isdigit() for c in full) / n,
            "digits_host_ratio": sum(c.isdigit() for c in host) / max(len(host), 1),
            "letters_url_ratio": sum(c.isalpha() for c in full) / n,
            "host_to_url_ratio": len(host) / n,
            "subdomain_count": 0 if is_ip else len(sub_labels),
            "path_depth": len([p for p in path.split("/") if p]),
            "n_query_params": len([q for q in query.split("&") if q]),
            "tld_len": len(tld),
            "has_ip_host": int(is_ip), "has_port": int(bool(re.search(r":\d+$", netloc_raw.rsplit("@", 1)[-1]))),
            "has_at": int("@" in full or "@" in netloc_raw), "has_userinfo": int("@" in netloc_raw),
            "double_slash_in_path": int("//" in path),
            "has_punycode": int("xn--" in host), "has_non_ascii": int(any(ord(c) > 127 for c in str(raw))),
            "pct_encoded_count": len(re.findall(r"%[0-9a-fA-F]{2}", full)),
            "hex_ratio_url": sum(c in "0123456789abcdef" for c in full_l) / n,
            "q_count": full.count("?"), "eq_count": full.count("="), "amp_count": full.count("&"),
            "underscore_count": full.count("_"), "tilde_count": full.count("~"), "hash_count": str(raw).count("#"),
            "entropy_url": _entropy(full_l), "entropy_host": _entropy(host),
            "entropy_path": _entropy(path_l), "entropy_reg_domain": _entropy(dom),
            "max_token_len_host": max((len(t) for t in host_tokens), default=0),
            "avg_token_len_host": float(np.mean([len(t) for t in host_tokens])) if host_tokens else 0.0,
            "n_tokens_host": len(host_tokens), "n_tokens_path": len(path_tokens),
            "vowel_ratio_reg_domain": (sum(c in _VOWELS for c in dom_letters) / len(dom_letters)) if dom_letters else 0.0,
            "max_consonant_run_reg_domain": best, "digit_letter_switches_host": switches,
            "susp_word_count_host": sw_host, "susp_word_count_path": sw_path,
            "susp_word_count_total": sw_host + sw_path,
            "brand_in_subdomain_or_path": b_sub_path, "brand_in_reg_domain_mismatch": b_dom_mis,
            "brand_mismatch_any": brand_any,
            "is_shortener": int(reg in SHORTENERS), "risky_tld": int(tld in RISKY_TLDS),
            "tld_is_cc": int(len(tld) == 2),
            "www_in_subdomain_not_first": int("www" in sub_labels[1:]),
            "http_in_path_or_host": int("http" in (path_l + host)),
            "path_has_file_ext_exe": exe_ext, "path_has_file_ext_web": web_ext,
            "long_digit_run_host": int(bool(re.search(r"\d{5,}", host))),
            "repeated_char_run_host": int(bool(re.search(r"(.)\1{3,}", host))),
        }
        return [float(vals[k]) for k in FEATURE_NAMES]
    except Exception:
        return [float("nan")] * len(FEATURE_NAMES)


def featurise(urls) -> pd.DataFrame:
    return pd.DataFrame([extract_features(u) for u in urls], columns=FEATURE_NAMES)


# --------------------------------------------------------------------------- #
# Data loading
# --------------------------------------------------------------------------- #
_PHISH_WORDS = {"phishing", "phish", "malicious", "malware", "bad", "defacement", "spam", "unsafe", "1phish"}
_BENIGN_WORDS = {"benign", "legitimate", "legit", "good", "safe", "clean", "normal"}
_URL_COLS = ["url", "URL", "Url", "link", "domain", "website", "address"]
_LABEL_COLS = ["label", "Label", "class", "Class", "status", "Status", "result", "Result", "type", "target", "phishing"]
_KNOWN_POPULAR_DOMAINS = {
    "apple.com", "amazon.com", "bbc.com", "bankofamerica.com", "chase.com",
    "cloudflare.com", "github.com", "google.com", "hsbc.co.uk", "instagram.com",
    "linkedin.com", "microsoft.com", "mozilla.org", "nasa.gov", "nytimes.com",
    "phishtank.com", "python.org", "reddit.com", "stackoverflow.com", "wikipedia.org",
    "youtube.com",
}


def load_dataset(spec: str, source_id: int) -> pd.DataFrame:
    parts = [p.strip() for p in spec.split(",")]
    path = parts[0]
    url_col = parts[1] if len(parts) > 1 and parts[1] else None
    lab_col = parts[2] if len(parts) > 2 and parts[2] else None
    pos = parts[3] if len(parts) > 3 and parts[3] != "" else None

    df = pd.read_csv(path, low_memory=False)
    url_col = url_col or next((c for c in _URL_COLS if c in df.columns), None)
    lab_col = lab_col or next((c for c in _LABEL_COLS if c in df.columns), None)
    if url_col is None or lab_col is None:
        raise SystemExit(f"{path}: could not detect url/label columns; columns = {list(df.columns)}")

    raw = df[lab_col]
    if pos is not None:
        y = raw.astype(str).str.strip().str.lower().eq(str(pos).strip().lower()).astype(int)
    else:
        low = raw.astype(str).str.strip().str.lower()
        known = low.isin(_PHISH_WORDS | _BENIGN_WORDS)
        if known.mean() < 0.95:
            raise SystemExit(
                f"{path}: label column '{lab_col}' is numeric/ambiguous. Pass the value that means "
                f"PHISHING, e.g. --data {path},{url_col},{lab_col},1 (PhiUSIIL needs 0)."
            )
        y = low.isin(_PHISH_WORDS).astype(int)
        df = df[known.values]
        raw = raw[known.values]
    positive_domains = df.loc[y.loc[df.index].astype(bool), url_col].map(registered_domain)
    popular_fraction = positive_domains.isin(_KNOWN_POPULAR_DOMAINS).mean()
    if popular_fraction > 0.01:
        raise SystemExit(
            f"{path}: phishing class contains {popular_fraction:.2%} known-popular domains; "
            "the phishing value is likely wrong or the source is not a phishing feed."
        )
    out = pd.DataFrame({"url": df[url_col].astype(str), "y": y.loc[df.index].values, "source": source_id})
    return out


def prepare(df: pd.DataFrame, per_domain_cap: int) -> pd.DataFrame:
    df = df.copy()
    df["key"] = df["url"].str.strip().str.lower().str.replace(r"^[a-z]+://", "", regex=True).str.rstrip("/")
    df = df.drop_duplicates("key")
    # a URL labelled both ways across sources is noise -> drop entirely
    conflict = df.groupby("key")["y"].nunique()
    df = df[~df["key"].isin(conflict[conflict > 1].index)]
    df["group"] = df["url"].map(registered_domain)
    df = df.sample(frac=1.0, random_state=SEED)  # shuffle, then keep first N per (domain, class)
    df = df[df.groupby(["group", "y"]).cumcount() < per_domain_cap]
    return df.reset_index(drop=True)


def augment(df: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    """Format-variant copies (same label) so the model ignores cosmetic differences."""
    rows = []
    for url, y, g, s in zip(df["url"], df["y"], df["group"], df["source"]):
        if rng.random() > 0.35:
            continue
        host, path, query, core = normalise_url(url) if _ok(url) else (None,) * 4
        if host is None:
            continue
        kind = rng.integers(0, 6)
        if kind == 0:
            new = "https://" + core
        elif kind == 1:
            new = "http://www." + core if not host.startswith("www.") else "http://" + core
        elif kind == 2:
            new = host  # host-only copy: forces host-level learning for BOTH classes
        elif kind == 3:
            new = core.rstrip("/") + ("/" if rng.random() < 0.5 else "")
        elif kind == 4:
            new = host + "/about"
        else:
            new = host + "/login"
        rows.append((new, y, g, s))
    return pd.DataFrame(rows, columns=["url", "y", "group", "source"])


def _ok(u) -> bool:
    try:
        normalise_url(u)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Model helpers
# --------------------------------------------------------------------------- #
def _metrics(y, p, thr) -> dict:
    from sklearn.metrics import (accuracy_score, average_precision_score, f1_score,
                                 precision_score, recall_score, roc_auc_score, confusion_matrix)
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred), "specificity": tn / max(tn + fp, 1),
        "f1": f1_score(y, pred), "roc_auc": roc_auc_score(y, p) if len(set(y)) > 1 else float("nan"),
        "pr_auc": average_precision_score(y, p) if len(set(y)) > 1 else float("nan"),
        "threshold": float(thr),
    }


def _make_xgb(params: dict, spw: float, n_jobs: int = -1, **extra):
    from xgboost import XGBClassifier
    base = dict(tree_method="hist", objective="binary:logistic", eval_metric="aucpr",
                scale_pos_weight=spw, random_state=SEED, n_jobs=n_jobs)
    base.update(params)
    base.update(extra)
    return XGBClassifier(**base)


def _pick_thresholds(y, p, target_fpr: float, target_recall: float):
    from sklearn.metrics import roc_curve
    fpr, tpr, thr = roc_curve(y, p)
    # operating point: best recall with FPR <= target
    ok = np.where(fpr <= target_fpr)[0]
    t_high = float(thr[ok[-1]]) if len(ok) else 0.5
    t_high = min(max(t_high, 0.5), 0.99)
    # "safe below" point: lowest score that still keeps recall >= target_recall
    ok2 = np.where(tpr >= target_recall)[0]
    t_low = float(thr[ok2[0]]) if len(ok2) else 0.2
    t_low = min(max(t_low, 0.02), t_high - 0.05)
    return t_low, t_high


# --------------------------------------------------------------------------- #
# Training
# --------------------------------------------------------------------------- #
def train(args) -> None:
    from sklearn.isotonic import IsotonicRegression
    from sklearn.model_selection import GroupKFold, GroupShuffleSplit, RandomizedSearchCV

    rng = np.random.default_rng(SEED)
    frames = [load_dataset(s, i) for i, s in enumerate(args.data)]
    names = [s.split(",")[0] for s in args.data]
    df = prepare(pd.concat(frames, ignore_index=True), args.per_domain_cap)
    if args.max_rows and len(df) > args.max_rows:
        df = df.sample(args.max_rows, random_state=SEED).reset_index(drop=True)
    print(f"[data] {len(df):,} unique URLs | phishing rate {df.y.mean():.3f} | "
          f"{df.group.nunique():,} registered domains | {len(frames)} source(s)")
    if df.y.nunique() < 2 or df.y.value_counts().min() < 50:
        raise SystemExit("Need at least 50 samples of each class.")

    # ---- grouped splits: 70 train / 10 val (early stop) / 10 calibration / 10 test
    def gsplit(frame, frac):
        gss = GroupShuffleSplit(n_splits=1, test_size=frac, random_state=SEED)
        a, b = next(gss.split(frame, frame.y, frame.group))
        return frame.iloc[a].reset_index(drop=True), frame.iloc[b].reset_index(drop=True)

    rest, test = gsplit(df, 0.10)
    rest, cal = gsplit(rest, 0.10 / 0.90)
    train_df, val = gsplit(rest, 0.10 / 0.80)
    print(f"[split] train {len(train_df):,} | val {len(val):,} | cal {len(cal):,} | test {len(test):,} (disjoint domains)")

    if not args.no_augment:
        aug = augment(train_df, rng)
        train_df = pd.concat([train_df, aug], ignore_index=True)
        print(f"[augment] +{len(aug):,} format-variant rows (train only)")

    Xtr, ytr, gtr = featurise(train_df.url), train_df.y.values, train_df.group.values
    Xva, yva = featurise(val.url), val.y.values
    Xca, yca = featurise(cal.url), cal.y.values
    Xte, yte = featurise(test.url), test.y.values
    spw = float((ytr == 0).sum() / max((ytr == 1).sum(), 1))
    print(f"[balance] scale_pos_weight = {spw:.3f}")

    # ---- regularised hyper-parameter search with grouped CV
    space = {
        "max_depth": [3, 4, 5, 6, 7],
        "learning_rate": [0.03, 0.05, 0.08, 0.1],
        "min_child_weight": [3, 5, 10, 20],
        "subsample": [0.6, 0.7, 0.8, 0.9],
        "colsample_bytree": [0.5, 0.6, 0.7, 0.8, 0.9],
        "gamma": [0, 0.5, 1, 2, 5],
        "reg_alpha": [0, 0.1, 0.5, 1, 5],
        "reg_lambda": [1, 2, 5, 10, 20],
    }
    search = RandomizedSearchCV(
        _make_xgb({}, spw, n_estimators=200), space, n_iter=args.n_iter,
        cv=GroupKFold(n_splits=4), scoring="average_precision", n_jobs=1,
        random_state=SEED, verbose=1, refit=False,
    )
    search.fit(Xtr, ytr, groups=gtr)
    best = search.best_params_
    print(f"[search] best CV PR-AUC {search.best_score_:.4f} | params {best}")

    # ---- final fit with early stopping on a disjoint validation set
    model = _make_xgb(best, spw, n_estimators=2000, early_stopping_rounds=40)
    model.fit(Xtr, ytr, eval_set=[(Xva, yva)], verbose=False)
    n_trees = int(model.best_iteration + 1)
    print(f"[fit] early stopping kept {n_trees} trees")

    # ---- calibration + thresholds (on data the model never saw)
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    iso.fit(model.predict_proba(Xca)[:, 1], yca)

    def predict_cal(X):
        return iso.predict(model.predict_proba(X)[:, 1])

    t_low, t_high = _pick_thresholds(yca, predict_cal(Xca), args.target_fpr, args.target_recall)
    print(f"[thresholds] safe < {t_low:.3f} <= suspicious < {t_high:.3f} <= phishing")

    # ---- honest evaluation
    report = {"test_in_distribution_held_out_domains": _metrics(yte, predict_cal(Xte), t_high)}
    p_tr = model.predict_proba(Xtr)[:, 1]
    report["train_vs_test_auc_gap"] = float(
        _metrics(ytr, p_tr, 0.5)["roc_auc"] - report["test_in_distribution_held_out_domains"]["roc_auc"]
    )
    print("[test] held-out domains:", json.dumps({k: round(v, 4) for k, v in
          report["test_in_distribution_held_out_domains"].items()}))
    print(f"[overfit check] train-test ROC-AUC gap = {report['train_vs_test_auc_gap']:.4f} "
          f"(>0.05 suggests memorisation)")

    # ---- leave-one-source-out (true cross-dataset generalisation)
    if len(frames) > 1:
        report["leave_one_source_out"] = {}
        for sid in sorted(df.source.unique()):
            tr, te = df[df.source != sid], df[df.source == sid]
            if te.y.nunique() < 2 or tr.y.nunique() < 2:
                continue
            tr = tr[~tr.group.isin(set(te.group))]  # no shared domains either
            m = _make_xgb(best, float((tr.y == 0).sum() / max((tr.y == 1).sum(), 1)),
                          n_estimators=n_trees)
            m.fit(featurise(tr.url), tr.y.values)
            pr = m.predict_proba(featurise(te.url))[:, 1]
            r = _metrics(te.y.values, pr, 0.5)
            report["leave_one_source_out"][names[sid]] = r
            print(f"[LOSO] hold out {names[sid]}: acc {r['accuracy']:.3f} f1 {r['f1']:.3f} "
                  f"auc {r['roc_auc']:.3f} spec {r['specificity']:.3f}")

    # ---- final refit on train+val (keeps tree count fixed), then save
    full = pd.concat([train_df, val], ignore_index=True)
    final = _make_xgb(best, spw, n_estimators=n_trees)
    final.fit(featurise(full.url), full.y.values)
    # re-calibrate on cal split with the final model so probabilities stay consistent
    iso_final = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    iso_final.fit(final.predict_proba(Xca)[:, 1], yca)
    p_cal = iso_final.predict(final.predict_proba(Xca)[:, 1])
    t_low, t_high = _pick_thresholds(yca, p_cal, args.target_fpr, args.target_recall)
    importances = dict(sorted(zip(FEATURE_NAMES, map(float, final.feature_importances_)),
                              key=lambda kv: -kv[1]))

    joblib.dump({
        "model": final, "calibrator": iso_final, "feature_names": FEATURE_NAMES,
        "feature_version": FEATURE_VERSION, "t_low": t_low, "t_high": t_high,
        "params": best, "n_trees": n_trees, "report": report, "importances": importances,
    }, args.out, compress=3)
    with open(args.out + ".report.json", "w") as f:
        json.dump({"report": report, "params": best, "n_trees": n_trees,
                   "t_low": t_low, "t_high": t_high, "importances": importances}, f, indent=2, default=float)
    print(f"[saved] {args.out} (+ .report.json)")
    print("[top features]", list(importances)[:8])


# --------------------------------------------------------------------------- #
# Inference API
# --------------------------------------------------------------------------- #
class PhishingDetector:
    """Load a trained bundle and score any URL-like input. Never raises on bad input."""

    def __init__(self, bundle: dict):
        if bundle.get("feature_version") != FEATURE_VERSION or bundle["feature_names"] != FEATURE_NAMES:
            raise RuntimeError("Model was trained with a different feature set; retrain it.")
        self.model, self.cal = bundle["model"], bundle["calibrator"]
        self.t_low, self.t_high = bundle["t_low"], bundle["t_high"]
        self.bundle = bundle

    @classmethod
    def load(cls, path: str) -> "PhishingDetector":
        return cls(joblib.load(path))

    def predict_proba(self, urls) -> np.ndarray:
        urls = [urls] if isinstance(urls, str) else list(urls)
        X = featurise(urls)
        return self.cal.predict(self.model.predict_proba(X)[:, 1])

    def predict(self, urls) -> list[dict]:
        urls = [urls] if isinstance(urls, str) else list(urls)
        probs = self.predict_proba(urls)
        out = []
        for u, p in zip(urls, probs):
            valid = _ok(u)
            if not valid:
                out.append({"url": u, "error": "unparseable url", "probability": None, "verdict": "unknown"})
                continue
            verdict = "phishing" if p >= self.t_high else ("suspicious" if p >= self.t_low else "safe")
            out.append({"url": u, "probability": round(float(p), 4), "verdict": verdict})
        return out


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("train")
    t.add_argument("--data", action="append", required=True,
                   help="path[,url_col,label_col,phishing_value]  (repeat per dataset)")
    t.add_argument("--out", default="phish_model.joblib")
    t.add_argument("--n-iter", type=int, default=25, help="random-search iterations")
    t.add_argument("--per-domain-cap", type=int, default=20)
    t.add_argument("--max-rows", type=int, default=0, help="subsample for speed (0 = all)")
    t.add_argument("--target-fpr", type=float, default=0.02, help="max false-positive rate for 'phishing' verdict")
    t.add_argument("--target-recall", type=float, default=0.97, help="recall kept below the 'safe' threshold")
    t.add_argument("--no-augment", action="store_true")

    p = sub.add_parser("predict")
    p.add_argument("--model", default="phish_model.joblib")
    p.add_argument("urls", nargs="+")

    args = ap.parse_args()
    if args.cmd == "train":
        train(args)
    else:
        print(json.dumps(PhishingDetector.load(args.model).predict(args.urls), indent=2))


if __name__ == "__main__":
    sys.exit(main())