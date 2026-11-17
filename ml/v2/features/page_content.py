"""
page_content.py — Page content feature extraction (Group 4).

Uses stdlib html.parser only (no BeautifulSoup).
When html is None → all features NaN (URL-only mode).
Never crashes; NaN on failure.
"""

from __future__ import annotations

import logging
import re
from html.parser import HTMLParser
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

nan = float("nan")

_URGENCY_KEYWORDS = [
    "verify", "suspend", "confirm", "click here", "urgent",
    "limited time", "account", "login", "password",
]

_FREE_CA_KWS = {"let's encrypt", "letsencrypt", "zerossl", "buypass"}


# ---------------------------------------------------------------------------
# Minimal HTML parser (stdlib)
# ---------------------------------------------------------------------------

class _PageParser(HTMLParser):
    """Collect relevant page elements."""

    def __init__(self, page_host: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_host = page_host.lower()

        # Forms
        self.form_actions: list[str] = []
        self.has_null_action = False
        self.has_password_field = False
        self.has_card_field = False
        self.has_otp_field = False

        # Scripts / CSS / Links
        self.script_srcs: list[str] = []
        self.css_hrefs: list[str] = []
        self.link_hrefs: list[str] = []
        self.all_links: list[str] = []

        # iframes
        self.hidden_iframe_count = 0

        # Obfuscation markers in inline scripts
        self.js_obfuscation_markers = 0
        self._obfus_total = 0

        # Misc
        self.right_click_disabled = False
        self.meta_refresh_present = False
        self.title_text = ""
        self._in_title = False
        self._in_body = False

        # Text accumulation
        self._text_chars = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)

        if tag == "title":
            self._in_title = True

        elif tag == "body":
            self._in_body = True
            # oncontextmenu="return false"
            ocm = (attr.get("oncontextmenu") or "").lower()
            if "return false" in ocm:
                self.right_click_disabled = True

        elif tag == "form":
            action = attr.get("action") or ""
            if not action or action.strip() in ("", "#"):
                self.has_null_action = True
            self.form_actions.append(action)

        elif tag == "input":
            itype = (attr.get("type") or "").lower()
            iname = (attr.get("name") or "").lower()
            if itype == "password":
                self.has_password_field = True
            # OTP field heuristic
            if itype in ("number", "tel") and any(k in iname for k in ("otp", "pin", "code", "verify")):
                self.has_otp_field = True
            # Card field
            if any(k in iname for k in ("card", "cvv", "cc", "cvc", "cardnumber", "pan")):
                self.has_card_field = True

        elif tag == "script":
            src = attr.get("src", "")
            if src:
                self.script_srcs.append(src)
            # oncontextmenu on script tag (rare but check body)
            ocm = (attr.get("oncontextmenu") or "").lower()
            if "return false" in ocm:
                self.right_click_disabled = True

        elif tag == "link":
            rel = (attr.get("rel") or "").lower()
            href = attr.get("href", "")
            if "stylesheet" in rel and href:
                self.css_hrefs.append(href)

        elif tag == "a":
            href = attr.get("href", "")
            if href:
                self.all_links.append(href)

        elif tag == "iframe":
            style = (attr.get("style") or "").lower()
            width = (attr.get("width") or "").strip()
            height = (attr.get("height") or "").strip()
            hidden = (
                "display:none" in style.replace(" ", "")
                or "visibility:hidden" in style.replace(" ", "")
                or width == "0"
                or height == "0"
            )
            if hidden:
                self.hidden_iframe_count += 1

        elif tag == "meta":
            http_equiv = (attr.get("http-equiv") or "").lower()
            if http_equiv == "refresh":
                self.meta_refresh_present = True

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_text += data
        # Count text characters (rough proxy)
        self._text_chars += len(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False


def _is_external(src: str, page_host: str) -> bool:
    """Return True if src is an absolute URL pointing to a different host."""
    if not src or src.startswith("data:"):
        return False
    if src.startswith("//"):
        host = urlparse("https:" + src).hostname or ""
    elif src.startswith("http"):
        host = urlparse(src).hostname or ""
    else:
        return False  # relative
    return host.lower() != page_host.lower()


# ---------------------------------------------------------------------------
# Obfuscation scan on raw HTML
# ---------------------------------------------------------------------------

_OBFUS_PATTERNS = [
    re.compile(r"\beval\s*\("),
    re.compile(r"\bunescape\s*\("),
    re.compile(r"fromCharCode\s*\("),
    re.compile(r"String\.fromChar"),
    re.compile(r"\\x[0-9a-fA-F]{2}"),
    re.compile(r"\\u[0-9a-fA-F]{4}"),
]


def _js_obfuscation_score(html: str) -> float:
    """Score 0-1 based on presence of obfuscation patterns."""
    hits = sum(1 for p in _OBFUS_PATTERNS if p.search(html))
    return min(1.0, hits / len(_OBFUS_PATTERNS))


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------

def extract_page_content_features(
    url: str,
    *,
    html: str | None = None,
) -> dict[str, float]:
    """
    Extract page content features from *html*.
    When html is None → all NaN.
    Never raises.
    """
    result: dict[str, float] = {
        "has_password_field":           nan,
        "has_card_field":               nan,
        "has_otp_field":                nan,
        "form_action_cross_domain":     nan,
        "null_action_form":             nan,
        "external_script_ratio":        nan,
        "external_css_ratio":           nan,
        "hidden_iframe_count":          nan,
        "js_obfuscation_score":         nan,
        "right_click_disabled":         nan,
        "meta_refresh_present":         nan,
        "title_domain_overlap":         nan,
        "urgency_keyword_score":        nan,
        "text_to_html_ratio":           nan,
        "login_form_on_unknown_domain": nan,
        "external_link_ratio":          nan,
    }

    if html is None:
        return result

    try:
        page_host = (urlparse(url).hostname or "").lower()
        parser = _PageParser(page_host)
        parser.feed(html)

        result["has_password_field"] = 1.0 if parser.has_password_field else 0.0
        result["has_card_field"]     = 1.0 if parser.has_card_field else 0.0
        result["has_otp_field"]      = 1.0 if parser.has_otp_field else 0.0
        result["null_action_form"]   = 1.0 if parser.has_null_action else 0.0
        result["hidden_iframe_count"] = float(parser.hidden_iframe_count)
        result["right_click_disabled"] = 1.0 if parser.right_click_disabled else 0.0
        result["meta_refresh_present"] = 1.0 if parser.meta_refresh_present else 0.0

        # Form action cross domain
        cross_domain_forms = 0
        for action in parser.form_actions:
            if action and not action.startswith("#"):
                action_host = ""
                if action.startswith("//"):
                    action_host = (urlparse("https:" + action).hostname or "").lower()
                elif action.startswith("http"):
                    action_host = (urlparse(action).hostname or "").lower()
                if action_host and action_host != page_host:
                    cross_domain_forms += 1
        result["form_action_cross_domain"] = (
            1.0 if cross_domain_forms > 0 else 0.0
        )

        # Script / CSS external ratios
        total_scripts = len(parser.script_srcs)
        ext_scripts = sum(1 for s in parser.script_srcs if _is_external(s, page_host))
        result["external_script_ratio"] = (
            ext_scripts / total_scripts if total_scripts > 0 else 0.0
        )

        total_css = len(parser.css_hrefs)
        ext_css = sum(1 for c in parser.css_hrefs if _is_external(c, page_host))
        result["external_css_ratio"] = (
            ext_css / total_css if total_css > 0 else 0.0
        )

        # External link ratio
        total_links = len(parser.all_links)
        ext_links = sum(1 for lnk in parser.all_links if _is_external(lnk, page_host))
        result["external_link_ratio"] = (
            ext_links / total_links if total_links > 0 else 0.0
        )

        # JS obfuscation score
        result["js_obfuscation_score"] = _js_obfuscation_score(html)

        # Title domain overlap
        title = parser.title_text.lower()
        if page_host:
            hostname_tokens = set(re.split(r"[\.\-_]", page_host)) - {"", "www"}
            if hostname_tokens:
                title_words = set(re.findall(r"[a-z]+", title))
                overlap = len(hostname_tokens & title_words) / len(hostname_tokens)
                result["title_domain_overlap"] = min(1.0, overlap)
            else:
                result["title_domain_overlap"] = 0.0
        else:
            result["title_domain_overlap"] = 0.0

        # Urgency keyword score
        all_text = re.sub(r"<[^>]+>", " ", html).lower()
        words = re.findall(r"[a-z]+", all_text)
        total_words = len(words)
        if total_words > 0:
            urgency_count = 0
            text_joined = " ".join(words)
            for kw in _URGENCY_KEYWORDS:
                # count occurrences (phrase aware)
                urgency_count += text_joined.count(kw.replace(" ", " "))
            result["urgency_keyword_score"] = min(1.0, urgency_count / total_words)
        else:
            result["urgency_keyword_score"] = 0.0

        # Text to HTML ratio
        html_len = len(html)
        if html_len > 0:
            result["text_to_html_ratio"] = min(1.0, parser._text_chars / html_len)
        else:
            result["text_to_html_ratio"] = 0.0

        # Login form on unknown domain
        from .url_lexical import _extract_registered_domain
        from .brand import _BRAND_REG_DOMAINS
        reg_domain = _extract_registered_domain(page_host)
        is_unknown = reg_domain not in _BRAND_REG_DOMAINS
        has_login_form = parser.has_password_field
        result["login_form_on_unknown_domain"] = (
            1.0 if (has_login_form and is_unknown) else 0.0
        )

    except Exception as exc:
        logger.warning("extract_page_content_features error: %s", exc)

    return result
