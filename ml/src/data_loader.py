"""
data_loader.py — Download and load the PhiUSIIL Phishing URL Dataset.

Primary source: UCI ML Repository (PhiUSIIL, 235 795 URLs).
Fallback: Synthetic 5 000-URL dataset constructed from known URL patterns
          (no network requests to target URLs — patterns only).
"""

from __future__ import annotations

import io
import logging
import os
import random
import zipfile
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
import requests

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Column names we care about from PhiUSIIL
# ─────────────────────────────────────────────────────────────────────────────
_URL_COL = "URL"
_LABEL_COL = "label"

# PhiUSIIL stores:  1 = phishing,  0 = legitimate
# We standardise to the same convention internally.

# ─────────────────────────────────────────────────────────────────────────────
# PhiUSIIL download
# ─────────────────────────────────────────────────────────────────────────────


def download_phiusiil(
    url: str,
    dest_dir: str | Path,
    timeout: int = 30,
) -> Path:
    """
    Download the PhiUSIIL dataset ZIP and extract the CSV.

    Parameters
    ----------
    url:
        Remote ZIP URL (from ``config.PHIUSIIL_URL``).
    dest_dir:
        Local directory where the CSV will be saved.
    timeout:
        HTTP request timeout in seconds.

    Returns
    -------
    Path
        Absolute path to the extracted CSV file.

    Raises
    ------
    RuntimeError
        If the download or extraction fails.
    """
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    csv_path = dest_dir / "phiusiil.csv"

    if csv_path.exists():
        logger.info("PhiUSIIL CSV already present at %s — skipping download.", csv_path)
        return csv_path

    logger.info("Downloading PhiUSIIL dataset from %s …", url)
    try:
        resp = requests.get(url, timeout=timeout, stream=True)
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        raise RuntimeError(
            f"Dataset download timed out after {timeout}s. "
            "Check your network or use the synthetic fallback."
        )
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Dataset download failed: {exc}")

    logger.info("Download complete. Extracting …")
    try:
        zf = zipfile.ZipFile(io.BytesIO(resp.content))
        # Find the CSV inside the ZIP
        csv_names = [n for n in zf.namelist() if n.lower().endswith(".csv")]
        if not csv_names:
            raise RuntimeError("No CSV found inside the downloaded ZIP.")
        # Pick the largest CSV (the main dataset)
        csv_name = max(csv_names, key=lambda n: zf.getinfo(n).file_size)
        logger.info("Extracting %s …", csv_name)
        with zf.open(csv_name) as src, open(csv_path, "wb") as dst:
            dst.write(src.read())
    except zipfile.BadZipFile as exc:
        raise RuntimeError(f"Downloaded file is not a valid ZIP: {exc}")

    logger.info("PhiUSIIL CSV saved to %s", csv_path)
    return csv_path


# ─────────────────────────────────────────────────────────────────────────────
# Load helpers
# ─────────────────────────────────────────────────────────────────────────────


def _inspect_columns(df: pd.DataFrame) -> dict[str, str]:
    """
    Return a mapping of {standard_name: actual_column_name} for the columns
    we care about, using a case-insensitive fuzzy search.
    """
    lower_map = {c.lower(): c for c in df.columns}
    mapping: dict[str, str] = {}

    # URL column
    for candidate in ("url", "urls", "url_string"):
        if candidate in lower_map:
            mapping["url"] = lower_map[candidate]
            break

    # Label column
    for candidate in ("label", "labels", "class", "phishing", "target"):
        if candidate in lower_map:
            mapping["label"] = lower_map[candidate]
            break

    # Optional network feature columns (may be pre-computed in dataset)
    for standard, candidates in {
        "qty_nameservers": ("qty_nameservers", "nameserver_count", "ns_count"),
        "is_spf_domain": ("is_spf_domain", "spf", "has_spf"),
        "time_domain_activation": (
            "time_domain_activation",
            "domain_age",
            "domain_age_days",
        ),
    }.items():
        for c in candidates:
            if c in lower_map:
                mapping[standard] = lower_map[c]
                break

    return mapping


def load_phiusiil(csv_path: str | Path) -> pd.DataFrame:
    """
    Load the PhiUSIIL CSV and return a normalised DataFrame with columns:
      - ``url``   (str)
      - ``label`` (int: 1=phishing, 0=legitimate)
      - Optional: ``qty_nameservers``, ``is_spf_domain``, ``time_domain_activation``

    Raises
    ------
    ValueError
        If the CSV doesn't contain required columns.
    """
    csv_path = Path(csv_path)
    logger.info("Loading PhiUSIIL CSV from %s …", csv_path)
    df = pd.read_csv(csv_path, low_memory=False)
    logger.info("Loaded %d rows, %d columns.", len(df), len(df.columns))

    col_map = _inspect_columns(df)
    logger.debug("Column mapping: %s", col_map)

    if "url" not in col_map:
        raise ValueError(
            f"Could not find a URL column in {csv_path}. "
            f"Available columns: {list(df.columns)}"
        )
    if "label" not in col_map:
        raise ValueError(
            f"Could not find a label column in {csv_path}. "
            f"Available columns: {list(df.columns)}"
        )

    out = pd.DataFrame()
    out["url"] = df[col_map["url"]].astype(str)
    out["label"] = pd.to_numeric(df[col_map["label"]], errors="coerce").astype(
        "Int64"
    )

    # Include optional pre-computed network features if present
    for feat in ("qty_nameservers", "is_spf_domain", "time_domain_activation"):
        if feat in col_map:
            out[feat] = pd.to_numeric(df[col_map[feat]], errors="coerce")

    # Drop rows where either url or label is null
    before = len(out)
    out = out.dropna(subset=["url", "label"])
    dropped = before - len(out)
    if dropped:
        logger.warning("Dropped %d rows with missing url/label.", dropped)

    out["label"] = out["label"].astype(int)
    logger.info(
        "Final dataset: %d rows. Label distribution: %s",
        len(out),
        out["label"].value_counts().to_dict(),
    )
    return out.reset_index(drop=True)


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic fallback dataset
# ─────────────────────────────────────────────────────────────────────────────

_LEGITIMATE_PATTERNS = [
    "https://www.google.com/search?q=python",
    "https://github.com/openai/gpt",
    "https://stackoverflow.com/questions/12345",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://docs.python.org/3/library/os.html",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.reddit.com/r/MachineLearning/",
    "https://news.ycombinator.com/",
    "https://www.nytimes.com/section/technology",
    "https://www.bbc.co.uk/news",
    "https://www.linkedin.com/in/johndoe",
    "https://twitter.com/openai",
    "https://www.microsoft.com/en-us/windows",
    "https://www.apple.com/iphone/",
    "https://www.spotify.com/us/premium/",
    "https://www.netflix.com/browse",
    "https://www.dropbox.com/home",
    "https://mail.google.com/mail/u/0/",
    "https://outlook.live.com/mail/0/",
]

_PHISHING_PATTERNS = [
    "http://paypal-secure-login.xyz/verify?token=abc123",
    "http://192.168.1.1/apple-id-confirm/login.php",
    "http://secure-account-microsoft.tk/update-billing",
    "http://amazon-order-verify.ml/signin?redirect=true",
    "http://login-facebook-security.ga/checkpoint",
    "http://netflix-billing-update.cf/account/payment",
    "http://google-account-verify.gq/security/check",
    "http://instagram-support-verify.ml/login/confirm",
    "http://bank-secure-login.xyz/account/verify",
    "http://ebay-account-suspended.tk/resolve",
    "http://paypal.confirm-wallet-update.ru/login",
    "http://apple.id-verify-account.cn/signin",
    "http://secure.microsoft-alert.info/warning",
    "http://amazon-customer-review.ru/win/prize",
    "http://wellsfargo-secure.online/account/alert",
    "http://chase-bank-alert.xyz/login",
    "http://coinbase-wallet-verify.ml/signin",
    "http://binance-security-alert.tk/account",
    "http://steam-free-games.ga/confirm",
    "http://login-verify-confirm-update.xyz/signin",
]


def _mutate_url(base_url: str, rng: random.Random) -> str:
    """Apply small random perturbations to a URL to generate variety."""
    mutations = [
        lambda u: u + f"?id={rng.randint(1000, 9999)}",
        lambda u: u.replace("login", "log-in"),
        lambda u: u + f"/{rng.randint(1, 99)}",
        lambda u: u,  # no change
    ]
    return rng.choice(mutations)(base_url)


def generate_synthetic_dataset(n: int = 5_000, seed: int = 42) -> pd.DataFrame:
    """
    Generate a synthetic phishing/legitimate URL dataset.

    This uses only known URL pattern strings — no network requests.
    The resulting DataFrame is clearly labelled as synthetic.

    Parameters
    ----------
    n:
        Total number of URLs to generate (approximately 50/50 split).
    seed:
        Random seed for reproducibility.

    Returns
    -------
    pd.DataFrame
        Columns: ``url``, ``label`` (1=phishing, 0=legitimate), ``synthetic``
    """
    rng = random.Random(seed)
    rows: list[dict] = []

    half = n // 2
    for _ in range(half):
        rows.append(
            {
                "url": _mutate_url(rng.choice(_LEGITIMATE_PATTERNS), rng),
                "label": 0,
                "synthetic": True,
            }
        )
    for _ in range(n - half):
        rows.append(
            {
                "url": _mutate_url(rng.choice(_PHISHING_PATTERNS), rng),
                "label": 1,
                "synthetic": True,
            }
        )

    df = pd.DataFrame(rows).sample(frac=1, random_state=seed).reset_index(drop=True)
    logger.warning(
        "Using SYNTHETIC dataset (%d rows). "
        "Metrics will NOT reflect real-world performance. "
        "Download the PhiUSIIL dataset for production training.",
        len(df),
    )
    return df


# ─────────────────────────────────────────────────────────────────────────────
# Primary entry point
# ─────────────────────────────────────────────────────────────────────────────


def load_dataset(
    data_dir: str | Path,
    phiusiil_url: str,
    download_timeout: int = 30,
    force_synthetic: bool = False,
) -> tuple[pd.DataFrame, bool]:
    """
    Attempt to load the PhiUSIIL dataset; fall back to synthetic if it fails.

    Returns
    -------
    (df, is_synthetic)
        ``df`` has columns ``url``, ``label``, and optional network feature cols.
        ``is_synthetic`` is ``True`` when the fallback was used.
    """
    data_dir = Path(data_dir)

    if not force_synthetic:
        csv_path = data_dir / "phiusiil.csv"
        if not csv_path.exists():
            try:
                csv_path = download_phiusiil(phiusiil_url, data_dir, download_timeout)
            except RuntimeError as exc:
                logger.error(
                    "PhiUSIIL download failed: %s\n"
                    "Falling back to synthetic dataset.",
                    exc,
                )
                return generate_synthetic_dataset(), True

        try:
            df = load_phiusiil(csv_path)
            return df, False
        except Exception as exc:
            logger.error(
                "Failed to load PhiUSIIL CSV: %s\nFalling back to synthetic dataset.",
                exc,
            )
            return generate_synthetic_dataset(), True

    return generate_synthetic_dataset(), True
