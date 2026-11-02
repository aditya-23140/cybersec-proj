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

# The public PhiUSIIL dataset encodes 1 = legitimate and 0 = phishing.
# We normalise it to the internal convention used by the project: 1 = phishing,
# 0 = legitimate.

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
    for candidate in (
        "url",
        "urls",
        "url_string",
        "uri",
        "website",
        "site",
        "page_url",
        "target_url",
    ):
        if candidate in lower_map:
            mapping["url"] = lower_map[candidate]
            break

    # Label column: accept both the canonical "label" name and common variants.
    for candidate in (
        "label",
        "labels",
        "class",
        "target",
        "result",
        "target_label",
        "is_phishing",
        "phishing",
    ):
        if candidate in lower_map:
            mapping["label"] = lower_map[candidate]
            break

    # URL-level columns used by the shared training/inference feature set.
    for standard, candidates in {
        "is_domain_ip": ("isdomainip", "is_domain_ip"),
        "has_obfuscation": ("hasobfuscation", "has_obfuscation"),
        "digit_ratio_url": ("degitratioinurl", "degitratiourl", "digit_ratio_url"),
    }.items():
        for c in candidates:
            if c in lower_map:
                mapping[standard] = lower_map[c]
                break

    return mapping


def _is_real_phiusiil_schema(columns: list[str]) -> bool:
    """Detect the public PhiUSIIL CSV, which has dataset-specific URL features."""
    column_names = {str(c).lower() for c in columns}
    return (
        "url" in column_names
        and "label" in column_names
        and {"urllength", "domainlength", "tldlength", "bank", "pay", "crypto"}
        & column_names
    )


def load_phiusiil(csv_path: str | Path) -> pd.DataFrame:
    """
    Load the PhiUSIIL CSV and return a normalised DataFrame with URL-level
    columns used by the training feature pipeline.

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

    # The public PhiUSIIL CSV encodes 1 = legitimate and 0 = phishing, but the
    # rest of this project uses the internal convention 1 = phishing and 0 = legitimate.
    if _is_real_phiusiil_schema(df.columns):
        out["label"] = out["label"].map({1: 0, 0: 1})

    # Include measured URL features if present.
    for feat in ("is_domain_ip", "has_obfuscation", "digit_ratio_url"):
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


def load_urlhaus_feed(
    url: str = "https://urlhaus.abuse.ch/downloads/csv_recent/",
    timeout: int = 60,
    max_rows: int = 50_000,
) -> pd.DataFrame:
    """Load recent malicious URLs published by URLhaus."""
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    content = response.content
    if content[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            csv_name = next(name for name in archive.namelist() if name.endswith(".csv"))
            content = archive.read(csv_name)
    rows = pd.read_csv(
        io.BytesIO(content),
        comment="#",
        header=None,
        names=[
            "id", "dateadded", "url", "urlhaus_link", "threat",
            "tags", "url_status",
        ],
        usecols=[0, 1, 2, 3, 4, 5, 6],
    )
    result = pd.DataFrame({"url": rows["url"].dropna().astype(str), "label": 1})
    result["source"] = "urlhaus"
    return result.head(max_rows).reset_index(drop=True)


def load_openphish_feed(
    url: str = "https://openphish.com/feed.txt",
    timeout: int = 60,
    max_rows: int = 50_000,
) -> pd.DataFrame:
    """Load phishing URLs from the OpenPhish community feed."""
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    urls = [
        line.strip()
        for line in response.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    result = pd.DataFrame({"url": urls[:max_rows], "label": 1})
    result["source"] = "openphish"
    return result


def load_tranco_domains(
    url: str = "https://tranco-list.eu/top-1m.csv.zip",
    timeout: int = 60,
    max_rows: int = 50_000,
) -> pd.DataFrame:
    """Load popular domains as benign examples from the Tranco list."""
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        csv_name = next(name for name in archive.namelist() if name.endswith(".csv"))
        with archive.open(csv_name) as csv_file:
            rows = pd.read_csv(csv_file, header=None, names=["rank", "domain"])
    result = pd.DataFrame(
        {"url": "https://" + rows["domain"].dropna().astype(str), "label": 0}
    )
    result["source"] = "tranco"
    return result.head(max_rows).reset_index(drop=True)


def load_multi_source_dataset(
    phiusiil_path: str | Path,
    phiusiil_url: str,
    openphish_url: str,
    tranco_url: str,
    data_dir: str | Path,
    timeout: int = 60,
    max_rows: int = 50_000,
) -> tuple[pd.DataFrame, bool]:
    """Combine independent public sources without silently substituting data."""
    frames: list[pd.DataFrame] = []
    synthetic = False
    try:
        phiusiil = load_phiusiil(phiusiil_path)
        phiusiil["source"] = "phiusiil"
        frames.append(phiusiil)
    except Exception as exc:
        logger.warning("PhiUSIIL unavailable: %s", exc)

    for loader, source_name, source_url in (
        (load_openphish_feed, "openphish", openphish_url),
        (load_tranco_domains, "tranco", tranco_url),
    ):
        try:
            frames.append(loader(source_url, timeout, max_rows))
        except Exception as exc:
            logger.warning("%s unavailable: %s", source_name, exc)

    if not frames:
        raise RuntimeError(
            "No real datasets could be loaded. Use --synthetic explicitly "
            "for offline development; production training must use real data."
        )

    combined = pd.concat(frames, ignore_index=True, sort=False)
    combined["url"] = combined["url"].astype(str).str.strip()
    combined = combined.drop_duplicates(subset=["url"], keep="first")
    logger.info(
        "Combined sources: rows=%d by_source=%s",
        len(combined),
        combined["source"].value_counts().to_dict(),
    )
    return combined.reset_index(drop=True), synthetic


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
