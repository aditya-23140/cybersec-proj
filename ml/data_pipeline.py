#!/usr/bin/env python3
"""Build derived training inputs without modifying the supplied datasets.

The crawler is intentionally static: it uses the hybrid detector's bounded
fetcher and never executes JavaScript. Run it in an isolated environment.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

import pandas as pd

import phishing_hybrid as hybrid
import phishing_model as pm


def common_crawl_urls(tranco_path: str, index: str, start: int, end: int,
                      domains: int, per_domain: int) -> pd.DataFrame:
    """Fetch real path URLs from a Common Crawl CDX index."""
    tranco = pd.read_csv(tranco_path, header=None, names=["rank", "domain"])
    tranco = tranco[tranco["rank"].between(start, end)].head(domains)
    def query_domain(domain: str) -> list[tuple[str, int, str]]:
        found = []
        query = f"{index}?url=*.{domain}/*&output=json&filter=status:200&filter=mime:text/html&collapse=urlkey&limit={per_domain}"
        request = Request(query, headers={"User-Agent": "FihhGuard-training-loader/1.0"})
        try:
            with urlopen(request, timeout=30) as response:
                for line in response:
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    url = str(item.get("url", "")).strip()
                    parsed = urlsplit(url)
                    if parsed.scheme in {"http", "https"} and parsed.path not in {"", "/"}:
                        found.append((url, 0, "common-crawl"))
        except Exception:
            pass
        return found
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=24) as pool:
        results = pool.map(query_domain, tranco["domain"].astype(str).tolist())
    rows = [item for result in results for item in result]
    return pd.DataFrame(rows, columns=["url", "label", "source"]).drop_duplicates("url")


def real_urls_from_index(path: str, url_column: str = "url",
                         rank_column: str = "rank", start: int = 10001,
                         end: int = 1_000_000) -> pd.DataFrame:
    """Load real URLs exported from Common Crawl or an internal-link crawl.

    This deliberately rejects domain-only Tranco rows: paths must come from
    the source index/crawl and are never synthesized here.
    """
    frame = pd.read_csv(path)
    if url_column not in frame:
        raise ValueError(f"{path}: missing URL column {url_column!r}")
    if rank_column in frame:
        frame = frame[frame[rank_column].between(start, end)]
    frame["url"] = frame[url_column].astype(str).str.strip()
    parsed = frame["url"].map(urlsplit)
    frame = frame[
        parsed.map(lambda p: p.scheme in {"http", "https"} and bool(p.netloc) and p.path not in {"", "/"})
    ]
    return frame[["url"]].drop_duplicates().assign(label=0, source="real-path-index")


def crawl_internal_links(seed_urls: list[str], limit: int = 0) -> pd.DataFrame:
    """Collect same-registered-domain links from real fetched HTML pages."""
    from bs4 import BeautifulSoup
    rows = []
    for seed in seed_urls:
        snap = hybrid.fetch_page(seed)
        html = snap.get("html")
        if not html:
            continue
        root = pm.registered_domain(seed)
        soup = BeautifulSoup(html, "html.parser")
        for anchor in soup.select("a[href]"):
            candidate = urljoin(seed, anchor.get("href", ""))
            parsed = urlsplit(candidate)
            if parsed.scheme not in {"http", "https"} or pm.registered_domain(candidate) != root:
                continue
            if parsed.path in {"", "/"}:
                continue
            rows.append(candidate)
            if limit and len(rows) >= limit:
                return pd.DataFrame({"url": rows}).drop_duplicates().assign(
                    label=0, source="internal-link-crawl"
                )
    return pd.DataFrame({"url": rows}).drop_duplicates().assign(
        label=0, source="internal-link-crawl"
    )


def internal_links_from_tranco(path: str, start: int, end: int,
                               domains: int, limit: int) -> pd.DataFrame:
    ranks = pd.read_csv(path, header=None, names=["rank", "domain"])
    ranks = ranks[ranks["rank"].between(start, end)].head(domains)
    seeds = [f"https://{d}/" for d in ranks["domain"].astype(str)]
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=16) as pool:
        pages = list(pool.map(lambda seed: crawl_internal_links([seed]), seeds))
    result = pd.concat(pages, ignore_index=True) if pages else pd.DataFrame(
        columns=["url", "label", "source"]
    )
    return result.drop_duplicates("url").head(limit or None)


def feed_urls(path: str, url_column: str = "url", label: int = 1,
              source: str = "feed") -> pd.DataFrame:
    """Load a current OpenPhish/PhishTank/URLhaus export into a derived CSV."""
    frame = pd.read_csv(path)
    if url_column not in frame:
        raise ValueError(f"{path}: missing URL column {url_column!r}")
    return pd.DataFrame({
        "url": frame[url_column].astype(str).str.strip(),
        "label": label,
        "source": source,
    }).drop_duplicates("url")


def cap_domains(frame: pd.DataFrame, cap: int) -> pd.DataFrame:
    """Cap registered domains so shared hosts cannot dominate a class."""
    out = frame.copy()
    out["_domain"] = out["url"].map(pm.registered_domain)
    out = out.groupby(["label", "_domain"], group_keys=False).head(cap)
    return out.drop(columns="_domain").reset_index(drop=True)


def crawl(frame: pd.DataFrame, out_dir: str, workers: int = 16) -> dict:
    """Fetch static snapshots and return per-class coverage."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    def one(row):
        url = row.url
        try:
            snap = hybrid.fetch_page(url)
            hybrid.save_snapshot(str(out), url, snap)
            return int(row.label), bool(snap.get("html"))
        except Exception as exc:
            hybrid.save_snapshot(str(out), url, {"error": f"{type(exc).__name__}: {exc}"})
        return int(row.label), False
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(one, [r for r in frame.itertuples(index=False)]))
    report = {}
    for label in sorted(frame.label.unique()):
        total = sum(r[0] == label for r in results)
        good = sum(r == (label, True) for r in results)
        report[str(label)] = {"total": total, "snapshots": good, "coverage": good / max(total, 1)}
    return report


def reachable_urls(frame: pd.DataFrame, workers: int = 16) -> pd.DataFrame:
    """Keep only URLs that return bounded HTML at verification time."""
    from concurrent.futures import ThreadPoolExecutor
    def check(url: str) -> bool:
        try:
            snap = hybrid.fetch_page(url)
            return bool(snap.get("html"))
        except Exception:
            return False
    with ThreadPoolExecutor(max_workers=workers) as pool:
        ok = list(pool.map(check, frame["url"].astype(str)))
    return frame.loc[ok].drop_duplicates("url").reset_index(drop=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build-legitimate")
    b.add_argument("--source", required=True,
                   help="CSV exported from Common Crawl or an internal-link crawl")
    b.add_argument("--out", required=True)
    b.add_argument("--url-column", default="url")
    b.add_argument("--rank-column", default="rank")
    c = sub.add_parser("crawl")
    c.add_argument("--csv", required=True)
    c.add_argument("--snapshots", required=True)
    c.add_argument("--workers", type=int, default=16)
    cc = sub.add_parser("common-crawl")
    cc.add_argument("--tranco", required=True)
    cc.add_argument("--index", required=True)
    cc.add_argument("--start", type=int, default=10001)
    cc.add_argument("--end", type=int, default=1_000_000)
    cc.add_argument("--domains", type=int, default=500)
    cc.add_argument("--per-domain", type=int, default=10)
    cc.add_argument("--out", required=True)
    il = sub.add_parser("internal-links")
    il.add_argument("--tranco", required=True)
    il.add_argument("--start", type=int, default=10001)
    il.add_argument("--end", type=int, default=1_000_000)
    il.add_argument("--domains", type=int, default=500)
    il.add_argument("--limit", type=int, default=0)
    il.add_argument("--out", required=True)
    vr = sub.add_parser("verify")
    vr.add_argument("--csv", required=True)
    vr.add_argument("--out", required=True)
    vr.add_argument("--workers", type=int, default=16)
    args = ap.parse_args()
    if args.command == "build-legitimate":
        real_urls_from_index(args.source, args.url_column, args.rank_column).to_csv(args.out, index=False)
        return
    if args.command == "common-crawl":
        common_crawl_urls(
            args.tranco, args.index, args.start, args.end, args.domains, args.per_domain
        ).to_csv(args.out, index=False)
        return
    if args.command == "internal-links":
        internal_links_from_tranco(
            args.tranco, args.start, args.end, args.domains, args.limit
        ).to_csv(args.out, index=False)
        return
    if args.command == "verify":
        reachable_urls(pd.read_csv(args.csv), args.workers).to_csv(args.out, index=False)
        return
    frame = pd.read_csv(args.csv)
    report = crawl(frame, args.snapshots, args.workers)
    print(report)
    if any(v["coverage"] < 0.20 for v in report.values()):
        raise SystemExit("snapshot coverage below 20% for at least one class")


if __name__ == "__main__":
    main()
