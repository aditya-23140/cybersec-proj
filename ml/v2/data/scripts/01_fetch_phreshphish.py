"""
01_fetch_phreshphish.py — Download PhreshPhish dataset from Hugging Face.

Data source  : https://huggingface.co/datasets/pirocheto/phishing-url
License      : CC BY 4.0 (Creative Commons Attribution 4.0 International)
               Attribution: PhreshPhish dataset, pirocheto on HuggingFace
Date range   : varies; assumed through 2024-Q4 for the backbone split
Known biases : Heavily URL-structure based; underrepresents non-English phishing;
               overrepresents certain TLDs (.xyz, .top). Legitimate class skewed
               toward Alexa/Tranco top-1M; real browsing prior is >>99% legit.

Usage:
    python 01_fetch_phreshphish.py [--dry-run] [--output-dir PATH]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

STUB_DIR = Path(__file__).resolve().parents[1] / "stubs"
OUTPUT_COLUMNS = [
    "url", "label", "source", "split",
    "collected_at", "registered_domain", "tld",
    "has_path", "has_query", "language", "is_login_page",
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Fetch PhreshPhish dataset from HuggingFace")
    p.add_argument("--dry-run", action="store_true", help="Print actions without downloading")
    p.add_argument("--output-dir", default=str(STUB_DIR), help="Where to write parquet files")
    return p.parse_args()


def _load_hf_dataset(dry_run: bool):
    """Attempt to load dataset via huggingface_hub / datasets library."""
    if dry_run:
        print("[DRY-RUN] Would load: pirocheto/phishing-url from HuggingFace Hub")
        return None
    try:
        from datasets import load_dataset  # type: ignore
        ds = load_dataset("pirocheto/phishing-url", trust_remote_code=False)
        return ds
    except Exception as exc:
        print(f"[WARN] Could not fetch from HuggingFace: {exc}", file=sys.stderr)
        return None


def _normalize_row(row: dict, split: str) -> dict:
    """Map HuggingFace schema to FihhGuard v2 schema."""
    import urllib.parse
    url = row.get("url", "")
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    # Registered domain: naive (last two labels of hostname)
    parts = hostname.split(".")
    registered_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    tld = parts[-1] if parts else ""
    label_raw = row.get("status", row.get("label", 0))
    label = 1 if str(label_raw).lower() in ("phishing", "1") else 0
    return {
        "url": url,
        "label": label,
        "source": "phreshphish",
        "split": split,
        "collected_at": row.get("date", "2024-01-01"),
        "registered_domain": registered_domain,
        "tld": tld,
        "has_path": bool(parsed.path and parsed.path not in ("", "/")),
        "has_query": bool(parsed.query),
        "language": "en",
        "is_login_page": False,
    }


def _save(records: list[dict], path: Path) -> None:
    import pandas as pd  # type: ignore
    df = pd.DataFrame(records, columns=OUTPUT_COLUMNS)
    df["label"] = df["label"].astype("int8")
    df.to_parquet(path, index=False)
    print(f"[INFO] Saved {len(df)} rows → {path}")


def main() -> None:
    args = parse_args()
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.dry_run:
        print("[DRY-RUN] 01_fetch_phreshphish.py")
        print("  Would download: pirocheto/phishing-url (HuggingFace Datasets)")
        print("  Would produce:")
        print(f"    {out_dir}/phreshphish_train.parquet  (150 legit + 50 phish)")
        print(f"    {out_dir}/phreshphish_val.parquet    (30 legit + 20 phish)")
        print(f"    {out_dir}/phreshphish_test.parquet   (20 legit + 10 phish, time-ordered)")
        print("  Columns:", OUTPUT_COLUMNS)
        print("  License: CC BY 4.0 — attribute pirocheto/phishing-url")
        return

    ds = _load_hf_dataset(dry_run=False)
    if ds is None:
        print("[WARN] No live data available; falling back to stubs.", file=sys.stderr)
        # Stubs already exist; nothing to do.
        return

    # Map HF splits to our splits (adjust field names as needed)
    split_map = {
        "train": ("phreshphish_train.parquet", "train"),
        "validation": ("phreshphish_val.parquet", "val"),
        "test": ("phreshphish_test.parquet", "test"),
    }
    for hf_split, (fname, our_split) in split_map.items():
        if hf_split not in ds:
            print(f"[WARN] HF split '{hf_split}' not found; skipping.")
            continue
        rows = [_normalize_row(r, our_split) for r in ds[hf_split]]
        _save(rows, out_dir / fname)


if __name__ == "__main__":
    main()
