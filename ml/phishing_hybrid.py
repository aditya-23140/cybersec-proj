#!/usr/bin/env python3
"""
phishing_hybrid.py - URL + page-content phishing detector (XGBoost).

Extends phishing_model.py (URL-only). Needs that file in the same folder.

WHAT IS NEW
-----------
1. PAGE CONTENT ANALYSIS (static HTML, no JavaScript is executed):
   forms / password+card+OTP inputs, where forms submit to, external-link ratios,
   hidden iframes, favicon origin, title-vs-domain mismatch, urgency keywords,
   JS obfuscation (eval/atob/fromCharCode), right-click blocking, meta refresh,
   redirect chain, invalid TLS, ...
2. NO HAND-WRITTEN BRAND LIST. Brands are discovered dynamically:
   * from a popular-domains list (Tranco top-N, ~10k brands, supplied by you), and
   * from the PAGE ITSELF: title / og:site_name / copyright text name a brand
     that the page's real domain does not belong to.
   Look-alike domains (paypa1, arnazon, gooogle, IDN homoglyphs, same name with a
   different TLD) are caught by edit-distance-1 matching against the list.
3. ONE MODEL, TWO MODES. Content features are randomly hidden during training, so the
   same model works when the page cannot be fetched (dead site, timeout, blocked):
   it falls back to URL-only scoring instead of failing or guessing.
4. Missingness is balanced across classes during training, so "page failed to load"
   is never learned as a proxy for "phishing".
5. SAFE FETCHER: blocks private/loopback/link-local/metadata IPs (SSRF), re-checks
   every redirect, caps size/time/redirects, no cookies, never executes JS.
6. EXPLANATIONS: every verdict lists the top signals that pushed the score.

WORKFLOW
--------
  pip install xgboost scikit-learn pandas numpy joblib tldextract requests beautifulsoup4

  # 1) Download page snapshots for your labelled URLs (do this on an isolated
  #    machine/VM; phishing pages die within hours, so crawl the same day you
  #    download the feed).
  python phishing_hybrid.py crawl --data phishtank.csv,url,label,1 \
         --data benign.csv,url,label,0 --out snapshots/ --workers 16

  # 2) Train (top-domains: Tranco CSV from tranco-list.eu, "rank,domain" or one per line)
  python phishing_hybrid.py train --data phishtank.csv,url,label,1 \
         --data benign.csv,url,label,0 --snapshots snapshots/ \
         --top-domains tranco_top1m.csv --top-n 10000 --out hybrid.joblib

  # 3) Use
  python phishing_hybrid.py analyze --model hybrid.joblib "https://suspicious.example/login"

  from phishing_hybrid import HybridDetector
  det = HybridDetector.load("hybrid.joblib")
  det.analyze("https://suspicious.example/login")              # fetches the page
  det.analyze(url, html=dom_html_from_browser_extension)       # you supply the (rendered) HTML
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import ipaddress
import json
import math
import os
import re
import socket
import sys
import time
import unicodedata
import warnings
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from functools import lru_cache
from urllib.parse import unquote, urljoin, urlsplit

import joblib
import numpy as np
import pandas as pd

import phishing_model as pm
from phishing_model import _split_host, normalise_url

warnings.filterwarnings("ignore")

NAN = float("nan")
HYBRID_VERSION = 2
MAX_HTML = 1_000_000

# the old hand-written brand list features are dropped; replaced by dynamic ones below
_DROP = {"brand_in_subdomain_or_path", "brand_in_reg_domain_mismatch", "brand_mismatch_any"}
URL_FEATURES = [f for f in pm.FEATURE_NAMES if f not in _DROP]
_URL_IDX = [pm.FEATURE_NAMES.index(f) for f in URL_FEATURES]

TOP_FEATURES = [
    "t_lookalike_dist", "t_brand_in_domain", "t_brand_in_sub_or_path",
    "t_n_brands_in_url", "t_shared_hosting", "t_tranco_rank_log",
]
SHARED_HOSTING = {
    "appspot.com", "blogspot.com", "firebaseapp.com", "github.io", "gitlab.io",
    "netlify.app", "pages.dev", "repl.co", "vercel.app", "web.app",
    "weeblysite.com", "wixsite.com", "square.site",
}

CONTENT_FEATURES = [
    "c_n_forms", "c_n_inputs", "c_n_password", "c_n_hidden_inputs", "c_n_email_inputs", "c_n_text_inputs",
    "c_has_password", "c_form_action_external", "c_form_action_null", "c_form_action_mailto",
    "c_form_action_ip", "c_form_action_insecure", "c_has_card_input", "c_has_otp_ssn_input",
    "c_password_autocomplete_off",
    "c_n_links", "c_ratio_ext_links", "c_ratio_null_links", "c_top_ext_domain_ratio", "c_n_ext_domains",
    "c_n_scripts", "c_ratio_ext_scripts", "c_n_iframes", "c_n_hidden_iframes", "c_ratio_ext_css",
    "c_n_images", "c_ratio_ext_images", "c_favicon_external", "c_favicon_missing",
    "c_text_len_log", "c_n_words", "c_title_len", "c_title_missing", "c_kw_count", "c_kw_density",
    "c_kw_in_title", "c_title_domain_overlap", "c_claimed_brand_n", "c_claimed_brand_mismatch",
    "c_has_eval", "c_has_atob", "c_has_unescape", "c_has_fromcharcode", "c_has_document_write",
    "c_rightclick_disabled", "c_has_window_open", "c_js_redirect", "c_hex_escape_density", "c_long_b64",
    "c_js_ratio", "c_meta_refresh", "c_noindex", "c_has_description", "c_has_copyright",
    "c_n_redirects", "c_redirect_cross_domain", "c_final_https", "c_html_len_log", "c_tls_invalid",
]
FEATURES = URL_FEATURES + TOP_FEATURES + CONTENT_FEATURES

# --------------------------------------------------------------------------- #
# Popular-domain knowledge (replaces the hard-coded brand list)
# --------------------------------------------------------------------------- #
_CONF = {ord(k): v for k, v in {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a", "!": "i", "|": "l",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ӏ": "l", "ѕ": "s",
    "ј": "j", "ο": "o", "ν": "v", "α": "a", "ρ": "p"}.items()}


def _canon(s: str) -> str:
    """Fold homoglyphs / leetspeak / separators so 'paypa1', 'раураl', 'pay-pal' compare equal."""
    s = s.lower()
    try:
        if s.startswith("xn--"):
            s = s.encode().decode("idna")
    except Exception:
        pass
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c)).translate(_CONF)
    s = re.sub(r"[-_.]", "", s)
    return s.replace("rn", "m").replace("vv", "w")


def _dels(s):
    return [s[:i] + s[i + 1:] for i in range(len(s))]


def _swaps(s):
    return [s[:i] + s[i + 1] + s[i] + s[i + 2:] for i in range(len(s) - 1)]


class TopDomains:
    """Popular registered domains -> brand names, look-alike index (edit distance <= 1)."""

    def __init__(self, domains):
        self.domains = [d.strip().lower() for d in domains if d and "." in d]
        self.reg = set(self.domains)
        self.rank = {d: i + 1 for i, d in enumerate(self.domains)}
        self.trusted_reg = set(self.domains[:10_000])
        self.labels, self.exact, self.variants = {}, {}, set()
        for rank, d in enumerate(self.domains):
            label = _split_host(d)[1]
            if not label:
                continue
            if len(label) >= 5 or (len(label) == 4 and rank < 3000):
                self.labels.setdefault(label, d)
            c = _canon(label)
            if len(c) >= 5:
                self.exact.setdefault(c, d)
                self.variants.add(c)
                self.variants.update(_dels(c))

    @classmethod
    def from_file(cls, path, n=10000):
        out = []
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                tok = line.strip().split(",")[-1].strip().strip('"').lower()
                if "." in tok and " " not in tok:
                    out.append(tok)
                if len(out) >= n:
                    break
        if not out:
            raise SystemExit(f"{path}: no domains found")
        return cls(out)

    def brand_hit(self, tok):
        r = self.labels.get(tok)
        if r:
            return r
        c = _canon(tok)
        return self.exact.get(c) if len(c) >= 5 else None

    def hits_in_label(self, label, reg):
        hits = set()
        for tok in re.findall(r"[a-z0-9]{4,}", label.lower()):
            r = self.brand_hit(tok)
            if r and r != reg:
                hits.add(r)
        c = _canon(label)
        for L in range(6, min(len(c), 14) + 1):
            for i in range(len(c) - L + 1):
                r = self.exact.get(c[i:i + L])
                if r and r != reg:
                    hits.add(r)
        return hits

    def lookalike(self, dom, reg):
        """0 = same name as a popular brand on another domain, 1 = one typo away, 2 = none."""
        if reg in self.reg or len(dom) < 5:
            return 2
        c = _canon(dom)
        if c in self.exact:
            return 0
        if c in self.variants or any(v in self.variants for v in _dels(c)) or \
                any(t in self.exact for t in _swaps(c)):
            return 1
        return 2

    def is_exact_popular(self, host):
        """Trust only exact roots in the top 10,000; rank is independent."""
        try:
            _sub, _dom, _suffix, reg = _split_host(host)
            return reg in self.trusted_reg and host in {reg, f"www.{reg}"}
        except Exception:
            return False


_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def top_features(url, top):
    n = len(TOP_FEATURES)
    if top is None:
        return [NAN] * n
    try:
        host, path, query, _ = normalise_url(url)
        if _IP_RE.match(host):
            return [2, 0, 0, 0, 0, math.log1p(1_000_000)]
        sub, dom, _suf, reg = _split_host(host)
        reg = reg or host
        look = top.lookalike(dom, reg) if dom else 2
        h_dom = top.hits_in_label(dom, reg) if dom else set()
        h_sp = set()
        for tok in re.findall(r"[a-z0-9]{4,}", f"{sub} {unquote(path)} {query}".lower()):
            r = top.brand_hit(tok)
            if r and r != reg:
                h_sp.add(r)
        return [look, int(bool(h_dom)), int(bool(h_sp)), len(h_dom | h_sp),
                int(reg in SHARED_HOSTING), math.log1p(top.rank.get(reg, 1_000_000))]
    except Exception:
        return [NAN] * n


# --------------------------------------------------------------------------- #
# Safe page fetcher
# --------------------------------------------------------------------------- #
FETCH_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0 Safari/537.36")


class BlockedTarget(Exception):
    pass


def _check_public(host, port):
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise OSError(f"dns failure: {e}")
    for ip in {i[4][0].split("%")[0] for i in infos}:
        a = ipaddress.ip_address(ip)
        if getattr(a, "ipv4_mapped", None):
            a = a.ipv4_mapped
        if not a.is_global:
            raise BlockedTarget(f"{host} resolves to non-public address {ip}")


def fetch_page(url, timeout=(5, 10), max_bytes=MAX_HTML, max_redirects=5, total_deadline=25,
               allow_private=False) -> dict:
    """Download HTML only. Never raises; failures are reported in snap['error']."""
    import requests
    import urllib3
    urllib3.disable_warnings()
    snap = {"url": url, "final_url": url, "status": None, "redirects": 0, "html": None,
            "error": None, "tls_invalid": False, "fetched_at": int(time.time())}
    u = str(url).strip()
    cands = [u] if "://" in u else ["https://" + u, "http://" + u]
    t_end = time.time() + total_deadline
    last = None
    for start in cands:
        sess = requests.Session()  # fresh session each time: no cookies carried over
        sess.headers.update({"User-Agent": FETCH_UA, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
                             "Accept-Language": "en-US,en;q=0.8"})
        try:
            cur, redirects = start, 0
            while True:
                p = urlsplit(cur)
                if p.scheme not in ("http", "https") or not p.hostname:
                    raise ValueError("unsupported scheme or missing host")
                hostp = f"[{p.hostname}]" if ":" in p.hostname else p.hostname
                cur = p._replace(netloc=hostp + (f":{p.port}" if p.port else "")).geturl()  # drop userinfo
                if not allow_private:
                    _check_public(p.hostname, p.port or (443 if p.scheme == "https" else 80))
                try:
                    r = sess.get(cur, timeout=timeout, allow_redirects=False, stream=True)
                except requests.exceptions.SSLError:
                    snap["tls_invalid"] = True
                    r = sess.get(cur, timeout=timeout, allow_redirects=False, stream=True, verify=False)
                if not allow_private:  # best-effort guard against DNS rebinding
                    try:
                        peer = r.raw._connection.sock.getpeername()[0]
                        a = ipaddress.ip_address(peer.split("%")[0])
                        if getattr(a, "ipv4_mapped", None):
                            a = a.ipv4_mapped
                        if not a.is_global:
                            r.close()
                            raise BlockedTarget(f"connected to non-public address {peer}")
                    except BlockedTarget:
                        raise
                    except Exception:
                        pass
                if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                    r.close()
                    redirects += 1
                    if redirects > max_redirects:
                        raise RuntimeError("too many redirects")
                    cur = urljoin(cur, r.headers["location"])
                    continue
                snap.update(status=r.status_code, final_url=cur, redirects=redirects)
                ctype = r.headers.get("content-type", "").lower()
                buf = bytearray()
                for chunk in r.iter_content(16384):
                    buf.extend(chunk)
                    if len(buf) >= max_bytes or time.time() > t_end:
                        break
                r.close()
                head = bytes(buf[:2048]).lower()
                if "html" in ctype or b"<html" in head or b"<!doctype" in head or b"<form" in head:
                    m = re.search(r"charset=([\w-]+)", ctype)
                    try:
                        snap["html"] = bytes(buf).decode(m.group(1) if m else "utf-8", errors="replace")
                    except LookupError:
                        snap["html"] = bytes(buf).decode("utf-8", errors="replace")
                else:
                    snap["error"] = "non-html content"
                return snap
        except BlockedTarget as e:
            snap["error"] = f"blocked: {e}"
            return snap
        except Exception as e:
            last = e
    snap["error"] = f"{type(last).__name__}: {last}"
    return snap


# --------------------------------------------------------------------------- #
# Snapshots (crawl once, train many times)
# --------------------------------------------------------------------------- #
def snap_path(d, url, ext=".json.gz"):
    h = hashlib.sha1(str(url).encode()).hexdigest()
    return os.path.join(d, h[:2], h + ext)


def save_snapshot(d, url, snap):
    ok = bool(snap.get("html"))
    path = snap_path(d, url, ".json.gz" if ok else ".fail")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if ok:
        with gzip.open(path, "wt", encoding="utf-8") as f:
            json.dump(snap, f)
    else:
        open(path, "w").write(str(snap.get("error")))


def load_snapshot(d, url):
    try:
        with gzip.open(snap_path(d, url), "rt", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def crawl(args):
    urls = []
    for i, spec in enumerate(args.data or []):
        urls += list(pm.load_dataset(spec, i)["url"])
    if args.urls_file:
        urls += [l.strip() for l in open(args.urls_file) if l.strip()]
    urls = list(dict.fromkeys(urls))
    if args.limit:
        urls = urls[:args.limit]
    todo = [u for u in urls if not (os.path.exists(snap_path(args.out, u)) or
                                    os.path.exists(snap_path(args.out, u, ".fail")))]
    print(f"[crawl] {len(urls):,} urls, {len(todo):,} to fetch (HTML text only, JS is never executed)")
    ok = 0

    def work(u):
        s = fetch_page(u, allow_private=args.allow_private)
        save_snapshot(args.out, u, s)
        return bool(s.get("html"))

    with ThreadPoolExecutor(args.workers) as ex:
        for n, r in enumerate(ex.map(work, todo), 1):
            ok += r
            if n % 500 == 0 or n == len(todo):
                print(f"[crawl] {n:,}/{len(todo):,} done, {ok:,} pages saved")


# --------------------------------------------------------------------------- #
# Content features
# --------------------------------------------------------------------------- #
KEYWORDS = [
    "verify your", "confirm your", "password", "log in", "login", "sign in", "signin", "account",
    "suspend", "locked", "unusual activity", "security alert", "update your", "expire", "urgent",
    "immediately", "billing", "payment", "bank", "credit card", "card number", "cvv", "social security",
    "one-time", "otp", "wallet", "seed phrase", "recovery phrase", "private key", "refund", "unauthorized",
    "restore access", "limited access", "click here",
]
_STOP = {"login", "sign", "account", "home", "welcome", "the", "and", "page", "official", "online", "www", "com"}
_CARD_RE = re.compile(r"card|cc-?num|cvv|cvc|expir|iban|routing", re.I)
_OTP_RE = re.compile(r"otp|one.?time|ssn|social.?sec|passcode|aadhaa?r|\bpan\b|\bpin\b", re.I)
_HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.I)


@lru_cache(maxsize=200_000)
def _reg_of_host(host):
    return _split_host(host)[3] or host


def _host_of(url):
    try:
        return normalise_url(url)[0]
    except Exception:
        return None


def _r(a, b):
    return a / b if b else 0.0


def content_features(snap, top) -> dict:
    out = dict.fromkeys(CONTENT_FEATURES, NAN)
    html = (snap or {}).get("html")
    if not html:
        return out
    try:
        from bs4 import BeautifulSoup
        html = html[:MAX_HTML]
        final = snap.get("final_url") or snap.get("url")
        page_host = _host_of(final) or ""
        page_reg = _reg_of_host(page_host) if page_host else ""
        page_label = _split_host(page_host)[1] if page_host else ""
        soup = BeautifulSoup(html, "html.parser")

        def classify(u):
            u = (u or "").strip()
            if u == "" or u.startswith("#") or u.lower().startswith("javascript:"):
                return "null", None
            if u.lower().startswith("mailto:"):
                return "mail", None
            a = urljoin(final, u)
            p = urlsplit(a)
            if p.scheme not in ("http", "https") or not p.hostname:
                return "skip", None
            reg = _reg_of_host(p.hostname.lower())
            return ("self" if reg == page_reg else "ext"), reg

        # ---- scripts
        scripts = soup.find_all("script")
        js = "\n".join(s.get_text() for s in scripts if not s.get("src"))
        ext_scripts = sum(1 for s in scripts if s.get("src") and classify(s["src"])[0] == "ext")

        # ---- forms / inputs
        forms = soup.find_all("form")
        inputs = soup.find_all("input")
        types = [(i.get("type") or "text").lower() for i in inputs]
        attrs = [" ".join(str(i.get(a, "")) for a in ("name", "id", "placeholder", "aria-label", "autocomplete"))
                 for i in inputs]
        fa = {"ext": 0, "null": 0, "mail": 0, "ip": 0, "insecure": 0}
        for f in forms:
            act = (f.get("action") or "").strip()
            kind, _ = classify(act)
            if kind in fa:
                fa[kind] += 1
            if kind != "null":
                h = _host_of(urljoin(final, act)) if kind in ("ext", "self") else None
                if h and _IP_RE.match(h):
                    fa["ip"] += 1
                if urljoin(final, act).startswith("http://") and str(final).startswith("https://"):
                    fa["insecure"] += 1

        # ---- links / media
        kinds = [classify(a.get("href")) for a in soup.find_all("a")]
        n_links = len(kinds)
        ext_regs = [r for k, r in kinds if k == "ext"]
        top_ext = max((ext_regs.count(x) for x in set(ext_regs)), default=0)
        imgs = soup.find_all("img")
        css = [l for l in soup.find_all("link") if "stylesheet" in " ".join(l.get("rel") or []).lower()]
        iframes = soup.find_all("iframe")
        hidden_if = sum(1 for f in iframes if _HIDDEN_STYLE.search(f.get("style") or "")
                        or str(f.get("width", "")).strip() in ("0", "1", "0px", "1px")
                        or str(f.get("height", "")).strip() in ("0", "1", "0px", "1px"))
        icons = [l for l in soup.find_all("link") if "icon" in " ".join(l.get("rel") or []).lower()]

        # ---- text
        title = soup.title.get_text(" ", strip=True) if soup.title else ""
        metas = {}
        for m in soup.find_all("meta"):
            k = (m.get("property") or m.get("name") or m.get("http-equiv") or "").lower()
            metas.setdefault(k, m.get("content") or "")
        for t in soup(["script", "style", "noscript", "template"]):
            t.extract()
        text = soup.get_text(" ", strip=True).lower()[:200_000]
        words = len(text.split())
        kw = sum(text.count(k) for k in KEYWORDS)
        title_l = title.lower()

        # ---- brand claims made by the page vs the domain it is really on
        claim_n = claim_mis = NAN
        if top is not None:
            parts = [title, metas.get("og:site_name", ""), metas.get("application-name", ""),
                     metas.get("apple-mobile-web-app-title", ""), metas.get("og:title", "")]
            h1 = soup.find("h1")
            if h1:
                parts.append(h1.get_text(" ", strip=True))
            m = re.search(r"(?:©|&copy;|copyright)\s*(?:\d{4})?\s*([^\n.|]{2,50})", text, re.I)
            if m:
                parts.append(m.group(1))
            toks = re.findall(r"[a-z0-9]{3,}", " ".join(parts).lower())
            cands = set(toks) | {a + b for a, b in zip(toks, toks[1:])} | \
                    {a + b + c for a, b, c in zip(toks, toks[1:], toks[2:])}
            claimed = {top.brand_hit(c) for c in cands if len(c) >= 4} - {None}
            claim_n = len(claimed)
            claim_mis = int(bool(claimed) and page_reg not in claimed)

        # ---- title vs domain
        ttoks = [t for t in re.findall(r"[a-z0-9]{3,}", title_l) if t not in _STOP]
        lab = _canon(page_label)
        overlap = NAN
        if ttoks and lab:
            overlap = sum(1 for t in ttoks if _canon(t) in lab or (len(lab) >= 4 and lab in _canon(t))) / len(ttoks)

        jl = js.lower()
        out.update({
            "c_n_forms": len(forms), "c_n_inputs": len(inputs), "c_n_password": types.count("password"),
            "c_n_hidden_inputs": types.count("hidden"), "c_n_email_inputs": types.count("email"),
            "c_n_text_inputs": types.count("text"), "c_has_password": int("password" in types),
            "c_form_action_external": fa["ext"], "c_form_action_null": fa["null"],
            "c_form_action_mailto": fa["mail"], "c_form_action_ip": fa["ip"],
            "c_form_action_insecure": fa["insecure"],
            "c_has_card_input": int(any(_CARD_RE.search(a) for a in attrs)),
            "c_has_otp_ssn_input": int(any(_OTP_RE.search(a) for a in attrs)),
            "c_password_autocomplete_off": int(any(t == "password" and (i.get("autocomplete") or "").lower() == "off"
                                                   for t, i in zip(types, inputs))),
            "c_n_links": n_links, "c_ratio_ext_links": _r(len(ext_regs), n_links),
            "c_ratio_null_links": _r(sum(1 for k, _ in kinds if k == "null"), n_links),
            "c_top_ext_domain_ratio": _r(top_ext, n_links), "c_n_ext_domains": len(set(ext_regs)),
            "c_n_scripts": len(scripts), "c_ratio_ext_scripts": _r(ext_scripts, len(scripts)),
            "c_n_iframes": len(iframes), "c_n_hidden_iframes": hidden_if,
            "c_ratio_ext_css": _r(sum(1 for l in css if classify(l.get("href"))[0] == "ext"), len(css)),
            "c_n_images": len(imgs),
            "c_ratio_ext_images": _r(sum(1 for i in imgs if classify(i.get("src"))[0] == "ext"), len(imgs)),
            "c_favicon_external": int(any(classify(l.get("href"))[0] == "ext" for l in icons)),
            "c_favicon_missing": int(not icons),
            "c_text_len_log": math.log1p(len(text)), "c_n_words": words, "c_title_len": len(title),
            "c_title_missing": int(not title), "c_kw_count": kw, "c_kw_density": 100.0 * kw / max(words, 1),
            "c_kw_in_title": sum(title_l.count(k) for k in KEYWORDS),
            "c_title_domain_overlap": overlap, "c_claimed_brand_n": claim_n, "c_claimed_brand_mismatch": claim_mis,
            "c_has_eval": int("eval(" in jl), "c_has_atob": int("atob(" in jl),
            "c_has_unescape": int("unescape(" in jl), "c_has_fromcharcode": int("fromcharcode" in jl),
            "c_has_document_write": int("document.write" in jl),
            "c_rightclick_disabled": int("contextmenu" in html.lower()),
            "c_has_window_open": int("window.open" in jl),
            "c_js_redirect": int(bool(re.search(r"location(\.href)?\s*=|location\.(replace|assign)\(", jl))),
            "c_hex_escape_density": 1000.0 * len(re.findall(r"\\x[0-9a-f]{2}|\\u[0-9a-f]{4}", jl)) / max(len(jl), 1),
            "c_long_b64": int(bool(re.search(r"[A-Za-z0-9+/]{300,}={0,2}", js))),
            "c_js_ratio": len(js) / max(len(html), 1),
            "c_meta_refresh": int("refresh" in metas), "c_noindex": int("noindex" in metas.get("robots", "").lower()),
            "c_has_description": int(bool(metas.get("description"))),
            "c_has_copyright": int(bool(re.search(r"©|&copy;|copyright", text))),
            "c_n_redirects": snap.get("redirects", 0),
            "c_redirect_cross_domain": int(_reg_of_host(_host_of(snap.get("url", "")) or "") != page_reg)
            if _host_of(snap.get("url", "")) else NAN,
            "c_final_https": int(str(final).startswith("https://")),
            "c_html_len_log": math.log1p(len(html)), "c_tls_invalid": int(bool(snap.get("tls_invalid"))),
        })
        return out
    except Exception:
        return dict.fromkeys(CONTENT_FEATURES, NAN)


# --------------------------------------------------------------------------- #
# Feature matrix
# --------------------------------------------------------------------------- #
_G_TOP = None


def _init_worker(top_domains):
    global _G_TOP
    _G_TOP = TopDomains(top_domains) if top_domains else None


def _content_task(args):
    url, snap_dir = args
    row = content_features(load_snapshot(snap_dir, url), _G_TOP)
    return [row[k] for k in CONTENT_FEATURES]


def content_matrix(urls, flags, snap_dir, top, workers):
    M = np.full((len(urls), len(CONTENT_FEATURES)), np.nan)
    idx = [i for i, f in enumerate(flags) if f]
    if idx and snap_dir:
        tasks = [(urls[i], snap_dir) for i in idx]
        doms = top.domains if top else None
        if workers > 1 and len(tasks) > 200:
            with ProcessPoolExecutor(workers, initializer=_init_worker, initargs=(doms,)) as ex:
                rows = list(ex.map(_content_task, tasks, chunksize=32))
        else:
            _init_worker(doms)
            rows = [_content_task(t) for t in tasks]
        M[idx] = rows
    return pd.DataFrame(M, columns=CONTENT_FEATURES)


def build_features(urls, flags, snap_dir, top, workers=1):
    urls = list(urls)
    Xu = pm.featurise(urls).iloc[:, _URL_IDX]
    Xu.columns = URL_FEATURES
    Xt = pd.DataFrame([top_features(u, top) for u in urls], columns=TOP_FEATURES)
    Xc = content_matrix(urls, list(flags), snap_dir, top, workers)
    return pd.concat([Xu, Xt, Xc], axis=1)[FEATURES]


def _mask(X):
    X = X.copy()
    X[CONTENT_FEATURES] = np.nan
    return X


# --------------------------------------------------------------------------- #
# Training
# --------------------------------------------------------------------------- #
def train(args):
    from sklearn.isotonic import IsotonicRegression
    from sklearn.model_selection import GroupKFold, GroupShuffleSplit, RandomizedSearchCV
    from sklearn.metrics import roc_auc_score

    rng = np.random.default_rng(pm.SEED)
    if args.n_iter < 25:
        raise SystemExit("--n-iter must be at least 25 for the production training path.")
    frames = []
    for i, spec in enumerate(args.data):
        source_path, *parts = [p.strip() for p in spec.split(",")]
        raw = pd.read_csv(source_path, low_memory=False)
        label_col = parts[1] if len(parts) > 1 and parts[1] else next(
            (c for c in pm._LABEL_COLS if c in raw.columns), None
        )
        if label_col is None:
            raise SystemExit(f"{source_path}: no label column for audit")
        print(f"[labels] {source_path}: raw {raw[label_col].value_counts(dropna=False).to_dict()}")
        frame = pm.load_dataset(spec, i)
        print(f"[labels] {source_path}: mapped y {frame.y.value_counts().to_dict()}")
        frames.append(frame)
    host_sources = {s.strip().lower() for s in args.host_level_sources.split(",") if s.strip()}
    for spec, frame in zip(args.data, frames):
        source_name = os.path.basename(spec.split(",")[0]).lower()
        if any(name in source_name for name in host_sources):
            frame["url"] = frame["url"].map(lambda u: pm.normalise_url(u)[0])
            print(f"[data] host-level URL normalization: {source_name}")
    names = [s.split(",")[0] for s in args.data]
    df = pm.prepare(pd.concat(frames, ignore_index=True), args.per_domain_cap)
    if args.max_rows and len(df) > args.max_rows:
        df = df.sample(args.max_rows, random_state=pm.SEED).reset_index(drop=True)
    if df.y.nunique() < 2 or df.y.value_counts().min() < 50:
        raise SystemExit("Need at least 50 samples of each class.")
    top = TopDomains.from_file(args.top_domains, args.top_n) if args.top_domains else None
    if top is None:
        print("[warn] no --top-domains: dynamic brand / look-alike features will be empty (much weaker)")
    print(f"[data] {len(df):,} URLs | phishing {df.y.mean():.3f} | {df.group.nunique():,} domains")

    # ---- snapshot coverage, balanced across classes so 'missing page' is not a label proxy
    if args.snapshots:
        df["has_snap"] = [os.path.exists(snap_path(args.snapshots, u)) for u in df.url]
    else:
        df["has_snap"] = False
        print("[warn] no --snapshots: training URL-only (content features all missing)")
    df["use_snap"] = df["has_snap"]
    cov = df.groupby("y")["has_snap"].mean()
    print(f"[content] page coverage  benign {cov.get(0, 0):.2%} | phishing {cov.get(1, 0):.2%}")
    if args.snapshots and cov.min() > 0:
        for c in (0, 1):
            if cov[c] > cov.min():
                drop = rng.random(len(df)) > (cov.min() / cov[c])
                df.loc[(df.y == c) & df.has_snap & drop, "use_snap"] = False
        print(f"[content] balanced coverage -> {df.groupby('y')['use_snap'].mean().round(3).to_dict()}")
    elif args.snapshots:
        print("[warn] one class has no pages at all; the model will not learn content signals reliably")
    if args.snapshots and cov.min() < 0.20:
        raise SystemExit("Snapshot coverage must be at least 20% in both classes.")
    if args.snapshots:
        successful = df.groupby("y")["has_snap"].sum()
        if successful.min() < args.min_snapshots_per_class:
            raise SystemExit(
                f"Need at least {args.min_snapshots_per_class} successful snapshots per class; "
                f"observed {successful.to_dict()}."
            )

    t0 = time.time()
    X_all = build_features(df.url, df.use_snap, args.snapshots, top, args.workers)
    print(f"[features] {X_all.shape[1]} features built in {time.time() - t0:.0f}s")
    y_all, g_all, has_all = df.y.values, df.group.values, df.use_snap.values

    def gsplit(idx, frac):
        sub = df.iloc[idx]
        a, b = next(GroupShuffleSplit(1, test_size=frac, random_state=pm.SEED).split(sub, sub.y, sub.group))
        return idx[a], idx[b]

    rest, te = gsplit(np.arange(len(df)), 0.10)
    rest, ca = gsplit(rest, 0.10 / 0.90)
    tr, va = gsplit(rest, 0.10 / 0.80)
    print(f"[split] train {len(tr):,} | val {len(va):,} | cal {len(ca):,} | test {len(te):,} (disjoint domains)")

    train_shortcut_urls = []
    train_shortcut_y = []

    def make_set(idx, mask_frac, augment=False):
        X = X_all.iloc[idx].reset_index(drop=True)
        y, g, has = y_all[idx], g_all[idx], has_all[idx]
        pick = np.where(has & (rng.random(len(idx)) < mask_frac))[0]  # content hidden copies
        Xs, ys, gs = [X, _mask(X.iloc[pick])], [y, y[pick]], [g, g[pick]]
        if augment and not args.no_augment:
            sub = df.iloc[idx][["url", "y", "group", "source"]].reset_index(drop=True)
            aug = pm.augment(sub, rng)
            if len(aug):
                Xs.append(build_features(aug.url, [False] * len(aug), None, top))
                ys.append(aug.y.values)
                gs.append(aug.group.values)
                if idx is tr:
                    train_shortcut_urls.extend(sub.url.tolist())
                    train_shortcut_urls.extend(aug.url.tolist())
                    train_shortcut_y.extend(sub.y.tolist())
                    train_shortcut_y.extend(aug.y.tolist())
        return pd.concat(Xs, ignore_index=True), np.concatenate(ys), np.concatenate(gs)

    Xtr, ytr, gtr = make_set(tr, 0.25, augment=True)
    Xva, yva, _ = make_set(va, 1.0)
    Xca, yca, _ = make_set(ca, 1.0)
    spw = float((ytr == 0).sum() / max((ytr == 1).sum(), 1))
    print(f"[balance] scale_pos_weight = {spw:.3f} | train rows incl. augmentation {len(ytr):,}")
    if train_shortcut_urls and len(set(train_shortcut_y)) > 1:
        shortcut = pm.featurise(train_shortcut_urls)
        shortcut["has_path"] = (shortcut["path_len"] > 0).astype(int)
        shortcut["has_query"] = (shortcut["query_len"] > 0).astype(int)
        shortcut["https"] = [int(str(u).lower().startswith("https://")) for u in train_shortcut_urls]
        shortcut_x = shortcut[["has_path", "has_query", "url_len", "https"]]
        audit_model = pm._make_xgb({"max_depth": 2, "n_estimators": 50}, 1.0, eval_metric="auc")
        audit_model.fit(shortcut_x, train_shortcut_y)
        shortcut_auc = float(roc_auc_score(
            train_shortcut_y, audit_model.predict_proba(shortcut_x)[:, 1]
        ))
        print(f"[shortcut-audit] exact post-normalization/augmentation rows AUC={shortcut_auc:.4f}")
        rep_shortcut_auc = shortcut_auc
    else:
        rep_shortcut_auc = float("nan")

    space = {"max_depth": [3, 4, 5, 6, 7], "learning_rate": [0.03, 0.05, 0.08, 0.1],
             "min_child_weight": [3, 5, 10, 20], "subsample": [0.6, 0.7, 0.8, 0.9],
             "colsample_bytree": [0.5, 0.6, 0.7, 0.8, 0.9], "gamma": [0, 0.5, 1, 2, 5],
             "reg_alpha": [0, 0.1, 0.5, 1, 5], "reg_lambda": [1, 2, 5, 10, 20]}
    search = RandomizedSearchCV(pm._make_xgb({}, spw, n_estimators=200), space, n_iter=args.n_iter,
                                cv=GroupKFold(n_splits=4), scoring="average_precision", n_jobs=1,
                                random_state=pm.SEED, verbose=1, refit=False)
    search.fit(Xtr, ytr, groups=gtr)
    best = search.best_params_
    print(f"[search] best CV PR-AUC {search.best_score_:.4f} | {best}")

    model = pm._make_xgb(best, spw, n_estimators=2000, early_stopping_rounds=40)
    model.fit(Xtr, ytr, eval_set=[(Xva, yva)], verbose=False)
    n_trees = int(model.best_iteration + 1)
    print(f"[fit] early stopping kept {n_trees} trees")

    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    iso.fit(model.predict_proba(Xca)[:, 1], yca)
    pred = lambda X: iso.predict(model.predict_proba(X)[:, 1])
    t_low, t_high = pm._pick_thresholds(yca, pred(Xca), args.target_fpr, args.target_recall)
    print(f"[thresholds] safe < {t_low:.3f} <= suspicious < {t_high:.3f} <= phishing")

    # ---- honest evaluation on unseen domains
    Xte, yte, has_te = X_all.iloc[te].reset_index(drop=True), y_all[te], has_all[te]
    p_full, p_url = pred(Xte), pred(_mask(Xte))
    rep = {"test_natural": pm._metrics(yte, p_full, t_high), "test_url_only_mode": pm._metrics(yte, p_url, t_high)}
    rep["shortcut_auc_model_input_rows"] = rep_shortcut_auc
    rep["training_class_prior_phishing"] = float(df.y.mean())
    rep["snapshot_coverage"] = {
        "has_snap_by_class": {str(k): int(v) for k, v in df.groupby("y").has_snap.sum().items()},
        "use_snap_by_class": {str(k): int(v) for k, v in df.groupby("y").use_snap.sum().items()},
    }
    if has_te.sum() > 50 and len(set(yte[has_te])) > 1:
        rep["pages_with_content__hybrid"] = pm._metrics(yte[has_te], p_full[has_te], t_high)
        rep["pages_with_content__url_only"] = pm._metrics(yte[has_te], p_url[has_te], t_high)
    fmt = lambda d: ({k: round(v, 4) for k, v in d.items()
                      if k in ("accuracy", "recall", "specificity", "f1", "roc_auc")}
                    if isinstance(d, dict) else d)
    for k, v in rep.items():
        print(f"[test] {k:34s}", fmt(v))
    rep["train_test_auc_gap"] = float(pm._metrics(ytr, model.predict_proba(Xtr)[:, 1], 0.5)["roc_auc"]
                                      - rep["test_natural"]["roc_auc"])
    print(f"[overfit check] train-test ROC-AUC gap = {rep['train_test_auc_gap']:.4f} (>0.05 = memorising)")

    if len(frames) > 1:
        rep["leave_one_source_out"] = {}
        for sid in sorted(df.source.unique()):
            held = np.where(df.source.values == sid)[0]
            trn = np.where(df.source.values != sid)[0]
            trn = trn[~np.isin(g_all[trn], set(g_all[held]))]
            if len(set(y_all[held])) < 2 or len(set(y_all[trn])) < 2:
                continue
            Xl, yl, _ = make_set(trn, 0.25)
            m = pm._make_xgb(best, float((yl == 0).sum() / max((yl == 1).sum(), 1)), n_estimators=n_trees)
            m.fit(Xl, yl)
            r = pm._metrics(y_all[held], m.predict_proba(X_all.iloc[held])[:, 1], 0.5)
            rep["leave_one_source_out"][names[sid]] = r
            print(f"[LOSO] held out {names[sid]}: {fmt(r)}")

    # ---- final refit on train+val, recalibrate
    Xf, yf, _ = make_set(np.concatenate([tr, va]), 0.25, augment=True)
    final = pm._make_xgb(best, float((yf == 0).sum() / max((yf == 1).sum(), 1)), n_estimators=n_trees)
    final.fit(Xf, yf)
    iso2 = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    iso2.fit(final.predict_proba(Xca)[:, 1], yca)
    t_low, t_high = pm._pick_thresholds(yca, iso2.predict(final.predict_proba(Xca)[:, 1]),
                                        args.target_fpr, args.target_recall)
    imp = dict(sorted(zip(FEATURES, map(float, final.feature_importances_)), key=lambda kv: -kv[1]))
    content_trained = bool(df.use_snap.any() and any(
        float(imp.get(name, 0.0)) > 0.0 for name in CONTENT_FEATURES
    ))
    bundle = {"model": final, "calibrator": iso2, "feature_names": FEATURES, "version": HYBRID_VERSION,
              "top_domains": top.domains if top else None, "t_low": t_low, "t_high": t_high,
              "params": best, "n_trees": n_trees, "report": rep, "importances": imp,
              "content_trained": content_trained}
    joblib.dump(bundle, args.out, compress=3)
    json.dump({"report": rep, "params": best, "t_low": t_low, "t_high": t_high,
               "importances": imp, "content_trained": content_trained},
              open(args.out + ".report.json", "w"), indent=2, default=float)
    print(f"[saved] {args.out} (+ .report.json)\n[top features] {list(imp)[:10]}")


# --------------------------------------------------------------------------- #
# Inference
# --------------------------------------------------------------------------- #
class HybridDetector:
    def __init__(self, bundle, allow_private=False, trust_popular=True):
        if bundle.get("version") != HYBRID_VERSION or bundle["feature_names"] != FEATURES:
            raise RuntimeError("Model/feature mismatch - retrain with this version of the script.")
        self.b, self.model, self.cal = bundle, bundle["model"], bundle["calibrator"]
        self.t_low, self.t_high = bundle["t_low"], bundle["t_high"]
        self.top = TopDomains(bundle["top_domains"]) if bundle.get("top_domains") else None
        self.allow_private = allow_private
        self.trust_popular = trust_popular

    @classmethod
    def load(cls, path, **kw):
        return cls(joblib.load(path), **kw)

    def _row(self, url, snap):
        urlf = [pm.extract_features(url)[i] for i in _URL_IDX]
        c = content_features(snap, self.top)
        return urlf + top_features(url, self.top) + [c[k] for k in CONTENT_FEATURES]

    def analyze(self, url, html=None, final_url=None, fetch=True, n_reasons=5) -> dict:
        """Score one URL. Pass html (e.g. the rendered DOM from a browser extension) to skip fetching."""
        if not pm._ok(url):
            return {"url": url, "verdict": "unknown", "probability": None, "error": "unparseable url"}
        host = pm.normalise_url(url)[0]
        _sub, _dom, _suffix, reg = _split_host(host)
        trusted_exact = bool(self.top and self.top.is_exact_popular(host))
        content_trained = bool(self.b.get("content_trained", False))
        if self.trust_popular and trusted_exact and html is None and not fetch:
            return {
                "url": url, "probability": 0.0, "verdict": "safe",
                "mode": "url-only", "content_ignored": not content_trained,
                "trusted_domain": True,
                "reasons": [{"feature": "known_popular_registered_domain", "value": reg, "push": 0.0}],
            }
        snap = None
        if html is not None:
            snap = {"url": url, "final_url": final_url or url, "html": html, "redirects": 0}
        elif fetch:
            snap = fetch_page(url, allow_private=self.allow_private)
        elif html is None:
            snap = {"url": url, "final_url": url, "html": None,
                    "error": "server fetch disabled; no caller-supplied HTML"}
        X = pd.DataFrame([self._row(url, snap)], columns=FEATURES)
        p = float(self.cal.predict(self.model.predict_proba(X)[:, 1])[0])
        content_used = bool(snap and snap.get("html") and content_trained)
        if self.trust_popular and trusted_exact:
            p = 0.0
        verdict = "phishing" if p >= self.t_high else ("suspicious" if p >= self.t_low else "safe")
        res = {"url": url, "probability": round(p, 4), "verdict": verdict,
               "mode": "url+content" if content_used else "url-only"}
        res["trusted_domain"] = trusted_exact
        if not content_used and not content_trained:
            res["content_ignored"] = True
        if snap and not snap.get("html"):
            res["fetch_error"] = snap.get("error")
        try:  # per-feature push toward 'phishing' (log-odds of the raw model)
            from xgboost import DMatrix
            contrib = self.model.get_booster().predict(DMatrix(X), pred_contribs=True)[0][:-1]
            order = np.argsort(-contrib)[:n_reasons]
            res["reasons"] = [{"feature": FEATURES[i], "value": None if np.isnan(X.iloc[0, i]) else round(float(X.iloc[0, i]), 3),
                               "push": round(float(contrib[i]), 3)} for i in order if contrib[i] > 0.05]
        except Exception:
            pass
        return res

    def analyze_many(self, urls, workers=8, **kw):
        with ThreadPoolExecutor(workers) as ex:
            return list(ex.map(lambda u: self.analyze(u, **kw), urls))


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("crawl")
    c.add_argument("--data", action="append", help="path[,url_col,label_col,phishing_value]")
    c.add_argument("--urls-file")
    c.add_argument("--out", default="snapshots")
    c.add_argument("--workers", type=int, default=16)
    c.add_argument("--limit", type=int, default=0)
    c.add_argument("--allow-private", action="store_true", help=argparse.SUPPRESS)

    t = sub.add_parser("train")
    t.add_argument("--data", action="append", required=True)
    t.add_argument("--snapshots")
    t.add_argument("--top-domains")
    t.add_argument("--top-n", type=int, default=10000)
    t.add_argument("--out", default="hybrid.joblib")
    t.add_argument("--n-iter", type=int, default=25)
    t.add_argument("--per-domain-cap", type=int, default=20)
    t.add_argument("--max-rows", type=int, default=0)
    t.add_argument("--workers", type=int, default=min(8, os.cpu_count() or 1))
    t.add_argument("--target-fpr", type=float, default=0.02)
    t.add_argument("--target-recall", type=float, default=0.97)
    t.add_argument("--host-level-sources", default="phiusiil",
                   help="comma-separated source filename fragments whose paths/queries are stripped")
    t.add_argument("--min-snapshots-per-class", type=int, default=5000)
    t.add_argument("--no-augment", action="store_true")

    a = sub.add_parser("analyze")
    a.add_argument("--model", default="hybrid.joblib")
    a.add_argument("--no-fetch", action="store_true", help="URL-only scoring")
    a.add_argument("--html", help="analyse this local HTML file as the page content")
    a.add_argument("--allow-private", action="store_true", help=argparse.SUPPRESS)
    a.add_argument("--no-popular-trust", action="store_true",
                   help="disable exact registered popular-domain trust")
    a.add_argument("urls", nargs="+")

    args = ap.parse_args()
    if args.cmd == "crawl":
        crawl(args)
    elif args.cmd == "train":
        train(args)
    else:
        det = HybridDetector.load(args.model, allow_private=args.allow_private,
                                  trust_popular=not args.no_popular_trust)
        html = open(args.html, encoding="utf-8", errors="replace").read() if args.html else None
        print(json.dumps([det.analyze(u, html=html, fetch=not args.no_fetch) for u in args.urls], indent=2))


if __name__ == "__main__":
    sys.exit(main())