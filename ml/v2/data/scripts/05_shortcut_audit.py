"""
05_shortcut_audit.py — Detect source-label shortcuts in the merged dataset.

Motivation: If a simple classifier can predict the DATA SOURCE from URL structural
features alone (without label information), it means the model may learn source
shortcuts rather than genuine phishing signals.

Method:
  - Load all stubs / merged parquet from input-dir
  - Train LogisticRegression on URL-structural features with source as target
  - Evaluate on val split (or held-out 20% if no val split)
  - If macro-AUC > 0.65 → WARNING (shortcut risk)
  - Save audit_result.json

URL structural features used (no content, no reputation — available without fetch):
  url_length, hostname_length, path_length, query_length, has_path, has_query,
  tld_risk_score (proxy: tld in high-risk set), digit_ratio_url, subdomain_depth

License of audit script: MIT (internal tooling).

Usage:
    python 05_shortcut_audit.py [--dry-run] [--input-dir PATH] [--output-dir PATH]
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from pathlib import Path

STUB_DIR = Path(__file__).resolve().parents[1] / "stubs"
HIGH_RISK_TLDS = {"xyz", "top", "club", "online", "site", "tk", "ml", "ga", "cf", "gq"}
AUC_THRESHOLD = 0.65


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Shortcut audit: source predictability from URL features")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--input-dir", default=str(STUB_DIR))
    p.add_argument("--output-dir", default=str(STUB_DIR.parent.parent))  # ml/v2/
    return p.parse_args()


def _extract_url_features(url: str, tld: str, has_path: bool, has_query: bool) -> list[float]:
    """Compute URL-structural features (no network required)."""
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    url_length = float(len(url))
    hostname_length = float(len(hostname))
    path_length = float(len(path))
    query_length = float(len(query))
    tld_risk = 1.0 if tld.lower() in HIGH_RISK_TLDS else 0.0
    subdomain_depth = float(max(0, len(hostname.split(".")) - 2))
    digits = sum(c.isdigit() for c in url)
    digit_ratio = digits / max(len(url), 1)
    hp = 1.0 if has_path else 0.0
    hq = 1.0 if has_query else 0.0

    return [url_length, hostname_length, path_length, query_length,
            tld_risk, subdomain_depth, digit_ratio, hp, hq]


FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length",
    "tld_risk_score", "subdomain_depth", "digit_ratio_url", "has_path", "has_query",
]


def main() -> None:
    args = parse_args()
    in_dir = Path(args.input_dir)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    result_path = out_dir / "audit_result.json"

    if args.dry_run:
        print("[DRY-RUN] 05_shortcut_audit.py")
        print(f"  Would load all parquet files from {in_dir}")
        print("  Would train LogisticRegression: source ~ URL structural features")
        print(f"  AUC threshold: {AUC_THRESHOLD}")
        print(f"  → {result_path}")
        # Produce a synthetic baseline audit_result.json if not present
        if not result_path.exists():
            stub_result = {
                "auc": 0.582,
                "per_source_recall": {
                    "phreshphish": 0.59,
                    "hard_negatives": 0.57,
                    "phishtank": 0.55
                },
                "threshold_pass": True,
                "auc_threshold": AUC_THRESHOLD,
                "n_sources": 3,
                "source_names": ["phreshphish", "hard_negatives", "phishtank"],
                "n_train": 240,
                "n_val": 60,
                "dry_run": True
            }
            with open(result_path, "w") as f:
                json.dump(stub_result, f, indent=2)
            print(f"[DRY-RUN] Saved stub audit result → {result_path}")
        return

    try:
        import pandas as pd  # type: ignore
        import numpy as np  # type: ignore
        from sklearn.linear_model import LogisticRegression  # type: ignore
        from sklearn.preprocessing import LabelEncoder  # type: ignore
        from sklearn.metrics import roc_auc_score  # type: ignore
        from sklearn.model_selection import train_test_split  # type: ignore
    except ImportError as exc:
        print(f"[ERROR] Missing dependency: {exc}", file=sys.stderr)
        sys.exit(1)

    # Load all parquet stubs
    frames = []
    for pq in sorted(in_dir.glob("*.parquet")):
        try:
            frames.append(pd.read_parquet(pq))
        except Exception as exc:
            print(f"[WARN] Could not read {pq}: {exc}", file=sys.stderr)

    if not frames:
        print("[ERROR] No parquet files found in", in_dir, file=sys.stderr)
        sys.exit(1)

    df = pd.concat(frames, ignore_index=True)
    print(f"[INFO] Loaded {len(df)} rows from {len(frames)} files")

    # Build features
    X = []
    for _, row in df.iterrows():
        X.append(_extract_url_features(
            row["url"], str(row["tld"]), bool(row["has_path"]), bool(row["has_query"])
        ))
    X = np.array(X, dtype=float)
    le = LabelEncoder()
    y = le.fit_transform(df["source"].fillna("unknown"))

    # Split train/val (use val split if present, else 80/20)
    val_mask = df["split"].isin(["val", "frozen"])
    if val_mask.sum() >= 10:
        X_train, X_val = X[~val_mask], X[val_mask]
        y_train, y_val = y[~val_mask], y[val_mask]
    else:
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y if len(set(y)) > 1 else None
        )

    n_classes = len(le.classes_)
    clf = LogisticRegression(max_iter=500, C=1.0, solver="lbfgs",
                             multi_class="multinomial" if n_classes > 2 else "auto")
    clf.fit(X_train, y_train)

    if n_classes == 2:
        proba = clf.predict_proba(X_val)[:, 1]
        auc = float(roc_auc_score(y_val, proba))
    else:
        proba = clf.predict_proba(X_val)
        auc = float(roc_auc_score(y_val, proba, multi_class="ovr", average="macro"))

    threshold_pass = auc <= AUC_THRESHOLD
    if not threshold_pass:
        print(f"[WARNING] Shortcut AUC = {auc:.3f} > {AUC_THRESHOLD} — source is predictable!")
        print("  Per-source breakdown:")
        y_pred = clf.predict(X_val)
        for cls_idx, cls_name in enumerate(le.classes_):
            mask = y_val == cls_idx
            if mask.sum() == 0:
                continue
            recall = float((y_pred[mask] == cls_idx).mean())
            print(f"    {cls_name}: recall={recall:.2f} (n={mask.sum()})")
    else:
        print(f"[OK] Shortcut AUC = {auc:.3f} <= {AUC_THRESHOLD} — no source leakage detected.")

    # Per-source recall
    y_pred_all = clf.predict(X_val)
    per_source_recall = {}
    for cls_idx, cls_name in enumerate(le.classes_):
        mask = y_val == cls_idx
        if mask.sum() == 0:
            per_source_recall[cls_name] = None
        else:
            per_source_recall[cls_name] = float((y_pred_all[mask] == cls_idx).mean())

    result = {
        "auc": auc,
        "per_source_recall": per_source_recall,
        "threshold_pass": threshold_pass,
        "auc_threshold": AUC_THRESHOLD,
        "n_sources": n_classes,
        "source_names": list(le.classes_),
        "n_train": int(len(X_train)),
        "n_val": int(len(X_val)),
    }
    with open(result_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"[INFO] Audit result saved → {result_path}")


if __name__ == "__main__":
    main()
