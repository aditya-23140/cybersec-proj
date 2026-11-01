import src.data_loader as data_loader


class FakeResponse:
    text = "https://bad.example/login\n# comment\nhttps://evil.example/"

    def raise_for_status(self):
        return None


def test_load_openphish_feed(monkeypatch):
    monkeypatch.setattr(
        data_loader.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(),
    )

    result = data_loader.load_openphish_feed("feed")

    assert result.to_dict("records") == [
        {"url": "https://bad.example/login", "label": 1, "source": "openphish"},
        {"url": "https://evil.example/", "label": 1, "source": "openphish"},
    ]
