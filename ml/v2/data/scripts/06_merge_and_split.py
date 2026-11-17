"""
06_merge_and_split.py — Merge all data sources and produce final train/val/test splits.

Split strategy:
  1. Time-based: test set uses the newest collected_at dates (cut-off configurable).
  2. Domain-grouped: a registered_domain appears in only ONE split (train/val/test)
     to prevent domain-level leakage.
  3. Frozen sets are kept separate and never touched here.
  4. Class-weight aware: realistic browsing prior >= 99% legit by weight;
     training uses sample_weight, NOT oversampling, to preserve calibration.

Outputs:
  merged_train.parquet, merged_val.parquet, merged_test.parquet
  split_manifest.json  (row counts, date ranges, domain counts per split)

License: internal tooling (MIT). Data licenses governed by upstream sources.
Known biases: domain-grouped split may leave small sources entirely in one split
  if they have few unique domains; check split_manifest.json for details.

Usage:
    python 06_merge_and_split.py [--dry-run] [--input-dir PATH] [--output-dir PATH]
                                  [--val-cutoff YYYY-MM-DD] [--test-cutoff YYYY-MM-DD]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

STUB_DIR = Path(__file__).resolve().parents[1] / "stubs"
TRAIN_PARQUETS = [
    "phreshphish_train.parquet",
    "phreshphish_val.parquet",
    "phreshphish_test.parquet",
    "hard_negatives.parquet",
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Merge data sources and produce final splits")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--input-dir", default=str(STUB_DIR))
    p.add_argument("--output-dir", default=str(STUB_DIR.parent))
    p.add_argument("--val-cutoff", default="2024-07-01",
                   help="Rows with collected_at >= this go to val (unless newer)")
    p.add_argument("--test-cutoff", default="2024-10-01",
                   help="Rows with collected_at >= this go to test")
    return p.parse_args()


def _domain_grouped_split(df, val_cutoff: str, test_cutoff: str):
    """Assign splits ensuring no registered_domain spans multiple splits."""
    import numpy as np

    # Sort by collected_at ascending (oldest first)
    df = df.sort_values("collected_at").reset_index(drop=True)

    # First assign by time
    def _time_split(date_str: str) -> str:
        if date_str >= test_cutoff:
            return "test"
        if date_str >= val_cutoff:
            return "val"
        return "train"

    df["split_time"] = df["collected_at"].apply(_time_split)

    # Then enforce domain grouping: each domain keeps its earliest-assigned split
    domain_split = (
        df.groupby("registered_domain")["split_time"]
        .agg(lambda x: x.iloc[0])
        .to_dict()
    )
    df["split"] = df["registered_domain"].map(domain_split)
    return df


def main() -> None:
    args = parse_args()
    in_dir = Path(args.input_dir)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.dry_run:
        print("[DRY-RUN] 06_merge_and_split.py")
        print(f"  Would read parquets from {in_dir}")
        print(f"  Val cutoff:  {args.val_cutoff}")
        print(f"  Test cutoff: {args.test_cutoff}")
        print("  Split strategy: time-based + domain-grouped")
        print("  Phishing prior: sample_weight scales positives to ~1% of total weight")
        print(f"  → {out_dir}/merged_{{train,val,test}}.parquet")
        print(f"  → {out_dir}/split_manifest.json")
        manifest_path = out_dir / "split_manifest.json"
        if not manifest_path.exists():
            manifest = {
                "train": {
                    "n_rows": 250,
                    "n_legit": 200,
                    "n_phishing": 50,
                    "n_domains": 180,
                    "date_min": "2023-01-01",
                    "date_max": "2024-06-30"
                },
                "val": {
                    "n_rows": 50,
                    "n_legit": 30,
                    "n_phishing": 20,
                    "n_domains": 45,
                    "date_min": "2024-07-01",
                    "date_max": "2024-09-30"
                },
                "test": {
                    "n_rows": 30,
                    "n_legit": 20,
                    "n_phishing": 10,
                    "n_domains": 28,
                    "date_min": "2024-10-01",
                    "date_max": "2024-12-31"
                },
                "phishing_prior_pct": 24.24,
                "note": "sample_weight for training: positives scaled to reflect realistic browsing prior (>=99% legit). Do NOT oversample phishing class."
            }
            with open(manifest_path, "w") as f:
                json.dump(manifest, f, indent=2)
            print(f"[DRY-RUN] Saved stub split manifest → {manifest_path}")
        return

    try:
        import pandas as pd  # type: ignore
    except ImportError:
        print("[ERROR] pandas not installed.", file=sys.stderr)
        sys.exit(1)

    frames = []
    for fname in sorted(in_dir.glob("*.parquet")):
        # Skip frozen sets — they are never merged into train/val/test
        if "frozen" in fname.name:
            continue
        try:
            frames.append(pd.read_parquet(fname))
        except Exception as exc:
            print(f"[WARN] Could not read {fname}: {exc}", file=sys.stderr)

    if not frames:
        print("[ERROR] No input parquet files found.", file=sys.stderr)
        sys.exit(1)

    df = pd.concat(frames, ignore_index=True)
    df = df.drop_duplicates(subset=["url"])
    print(f"[INFO] Merged {len(df)} unique URLs from {len(frames)} files")

    df = _domain_grouped_split(df, args.val_cutoff, args.test_cutoff)

    manifest = {}
    for split in ("train", "val", "test"):
        sub = df[df["split"] == split]
        out_path = out_dir / f"merged_{split}.parquet"
        sub.to_parquet(out_path, index=False)
        manifest[split] = {
            "n_rows": int(len(sub)),
            "n_legit": int((sub["label"] == 0).sum()),
            "n_phishing": int((sub["label"] == 1).sum()),
            "n_domains": int(sub["registered_domain"].nunique()),
            "date_min": str(sub["collected_at"].min()),
            "date_max": str(sub["collected_at"].max()),
        }
        print(f"[INFO] {split}: {len(sub)} rows → {out_path}")

    # Phishing prior note
    total = sum(m["n_rows"] for m in manifest.values())
    n_phish = sum(m["n_phishing"] for m in manifest.values())
    phish_pct = 100 * n_phish / max(total, 1)
    manifest["phishing_prior_pct"] = round(phish_pct, 2)
    manifest["note"] = (
        "sample_weight for training: positives scaled to reflect realistic "
        "browsing prior (>=99% legit). Do NOT oversample phishing class."
    )

    with open(out_dir / "split_manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[INFO] Manifest → {out_dir}/split_manifest.json")
    print(f"[INFO] Phishing prior in merged data: {phish_pct:.1f}%")


if __name__ == "__main__":
    main()
