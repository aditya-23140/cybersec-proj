import io
import zipfile

import pandas as pd

from src.data_loader import load_tranco_domains, load_urlhaus_feed


class FakeResponse:
    def __init__(self, content):
        self.content = content

    def raise_for_status(self):
        return None


def test_load_urlhaus_feed_normalizes_malicious_urls(monkeypatch):
    payload = (
        b"# comment\n"
        b'"1","2026-01-01","https://bad.example/a","https://urlhaus","malware","tag","online"\n'
    )
    monkeypatch.setattr(
        "src.data_loader.requests.get", lambda *args, **kwargs: FakeResponse(payload)
    )

    result = load_urlhaus_feed("feed", max_rows=10)

    assert result.to_dict("records") == [
        {"url": "https://bad.example/a", "label": 1, "source": "urlhaus"}
    ]


def test_load_tranco_domains_normalizes_benign_urls(monkeypatch):
    csv = b"1,example.com\n2,example.org\n"
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("top-1m.csv", csv)
    monkeypatch.setattr(
        "src.data_loader.requests.get",
        lambda *args, **kwargs: FakeResponse(archive.getvalue()),
    )

    result = load_tranco_domains("feed", max_rows=10)

    assert result.to_dict("records") == [
        {"url": "https://example.com", "label": 0, "source": "tranco"},
        {"url": "https://example.org", "label": 0, "source": "tranco"},
    ]
