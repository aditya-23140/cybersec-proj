"""
03_fetch_out_of_time.py — Collect post-March-2025 phishing URLs for OOT evaluation.

Sources:
  1. PhishTank (https://phishtank.org/) — community-verified phishing URLs.
     License: CC BY-SA 2.5 (must attribute and share-alike).
  2. URLhaus (https://urlhaus.abuse.ch/) — abuse.ch malware/phishing URL feed.
     License: Creative Commons Zero (CC0) — public domain dedication.

Date range   : collected_at >= 2025-04-01 (strict out-of-time).
Known biases : PhishTank has volunteer verification lag (~hours); URLhaus skews
               toward malware distribution, not credential-harvesting phishing.
               Both over-represent recently registered domains; brand distribution
               mirrors attacker fashion (may differ from training brands).

Usage:
    python 03_fetch_out_of_time.py [--dry-run] [--output-dir PATH] [--n-rows 50]
"""
from __future__ import annotations

import argparse
import sys
import urllib.parse
from pathlib import Path

STUB_DIR = Path(__file__).resolve().parents[1] / "stubs"
OUTPUT_COLUMNS = [
    "url", "label", "source", "split",
    "collected_at", "registered_domain", "tld",
    "has_path", "has_query", "language", "is_login_page",
]
PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.csv.gz"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
OOT_CUTOFF = "2025-04-01"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Fetch out-of-time phishing URLs")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--output-dir", default=str(STUB_DIR))
    p.add_argument("--n-rows", type=int, default=50)
    p.add_argument("--source", choices=["phishtank", "urlhaus", "both"], default="both")
    return p.parse_args()


def _fetch_phishtank(cutoff: str) -> list[dict]:
    """Fetch PhishTank CSV, filter to >= cutoff date."""
    import gzip
    import io
    import urllib.request
    try:
        print(f"[INFO] Fetching PhishTank data from {PHISHTANK_URL}")
        with urllib.request.urlopen(PHISHTANK_URL, timeout=60) as resp:
            data = gzip.decompress(resp.read())
        import csv
        reader = csv.DictReader(io.StringIO(data.decode("utf-8")))
        rows = []
        for row in reader:
            submitted = row.get("submission_time", "")[:10]
            if submitted >= cutoff:
                rows.append(row)
        return rows
    except Exception as exc:
        print(f"[WARN] PhishTank fetch failed: {exc}", file=sys.stderr)
        return []


def _fetch_urlhaus(cutoff: str) -> list[dict]:
    """Fetch URLhaus CSV, filter to >= cutoff date."""
    import io
    import urllib.request
    try:
        print(f"[INFO] Fetching URLhaus data from {URLHAUS_URL}")
        with urllib.request.urlopen(URLHAUS_URL, timeout=60) as resp:
            text = resp.read().decode("utf-8")
        import csv
        rows = []
        for line in text.splitlines():
            if line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 3:
                continue
            date_added = parts[1].strip().strip('"')[:10]
            if date_added >= cutoff:
                rows.append({"url": parts[2].strip().strip('"'), "date_added": date_added})
        return rows
    except Exception as exc:
        print(f"[WARN] URLhaus fetch failed: {exc}", file=sys.stderr)
        return []


def _normalize_phishtank(row: dict) -> dict:
    url = row.get("url", "")
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    registered_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    tld = parts[-1] if parts else ""
    return {
        "url": url,
        "label": 1,
        "source": "phishtank",
        "split": "frozen",
        "collected_at": row.get("submission_time", "2025-04-01")[:10],
        "registered_domain": registered_domain,
        "tld": tld,
        "has_path": bool(parsed.path and parsed.path not in ("", "/")),
        "has_query": bool(parsed.query),
        "language": "en",
        "is_login_page": True,
    }


def _normalize_urlhaus(row: dict) -> dict:
    url = row.get("url", "")
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    registered_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    tld = parts[-1] if parts else ""
    return {
        "url": url,
        "label": 1,
        "source": "urlhaus",
        "split": "frozen",
        "collected_at": row.get("date_added", "2025-04-01"),
        "registered_domain": registered_domain,
        "tld": tld,
        "has_path": bool(parsed.path and parsed.path not in ("", "/")),
        "has_query": bool(parsed.query),
        "language": "en",
        "is_login_page": False,
    }


def main() -> None:
    args = parse_args()
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "out_of_time_phishing.parquet"

    if args.dry_run:
        print("[DRY-RUN] 03_fetch_out_of_time.py")
        print(f"  Would fetch PhishTank: {PHISHTANK_URL}")
        print(f"  Would fetch URLhaus:   {URLHAUS_URL}")
        print(f"  Filter: collected_at >= {OOT_CUTOFF}")
        print(f"  Rows target: {args.n_rows}")
        print(f"  → {out_path}")
        print("  Columns:", OUTPUT_COLUMNS)
        return

    records = []
    if args.source in ("phishtank", "both"):
        for row in _fetch_phishtank(OOT_CUTOFF):
            records.append(_normalize_phishtank(row))
    if args.source in ("urlhaus", "both"):
        for row in _fetch_urlhaus(OOT_CUTOFF):
            records.append(_normalize_urlhaus(row))

    if not records:
        print("[WARN] No live OOT data; stubs already exist.", file=sys.stderr)
        return

    import pandas as pd  # type: ignore
    records = records[: args.n_rows]
    df = pd.DataFrame(records, columns=OUTPUT_COLUMNS)
    df["label"] = df["label"].astype("int8")
    df.to_parquet(out_path, index=False)
    print(f"[INFO] Saved {len(df)} rows → {out_path}")


if __name__ == "__main__":
    main()
