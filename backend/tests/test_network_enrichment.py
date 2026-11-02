from services.network_enrichment import enrich_url
from services.risk_policy import apply_policy
from routes.predict import _build_explanation
import services.network_enrichment as network_enrichment


def test_reputation_hit_overrides_model():
    raw = {
        "prediction": "benign",
        "phishing_probability": 0.02,
        "network_signals": {
            "reputation": {
                "reputation_provider": "URLhaus",
                "reputation_hit": True,
            }
        },
    }

    result = apply_policy("https://example.com", raw, [], [])

    assert result["source"] == "reputation"
    assert result["risk_level"] == "dangerous"


def test_unavailable_tls_does_not_create_network_risk():
    raw = {
        "prediction": "benign",
        "phishing_probability": 0.1,
        "network_signals": {
            "tls": {
                "certificate_checked": False,
                "certificate_valid": False,
            },
            "whois": {},
        },
    }

    result = apply_policy("https://example.com", raw, [], [])

    assert result["source"] == "model"
    assert result["risk_level"] == "safe"


def test_enrichment_can_be_disabled(monkeypatch):
    monkeypatch.setattr(
        "services.network_enrichment.config.ENABLE_NETWORK_ENRICHMENT", False
    )

    result = enrich_url("https://example.com")

    assert result["enrichment_enabled"] is False
    assert result["dns"] == {}
    assert result["tls"] == {}


def test_whois_uses_configured_timeout(monkeypatch):
    calls = {}

    class FakeWhois:
        @staticmethod
        def whois(host, timeout, **kwargs):
            calls["host"] = host
            calls["timeout"] = timeout
            return {}

    monkeypatch.setitem(__import__("sys").modules, "whois", FakeWhois)
    monkeypatch.setattr(
        network_enrichment.config, "ENRICHMENT_TIMEOUT_SECONDS", 2.5
    )

    network_enrichment._whois_signals("example.com")

    assert calls == {"host": "example.com", "timeout": 2}


def test_whois_queries_registrable_domain(monkeypatch):
    calls = {}

    class FakeWhois:
        @staticmethod
        def whois(host, **kwargs):
            calls["host"] = host
            return {}

    monkeypatch.setitem(__import__("sys").modules, "whois", FakeWhois)
    network_enrichment._whois_signals.cache_clear()

    network_enrichment._whois_signals("login.example.com")

    assert calls["host"] == "example.com"


def test_timeout_status_is_explicit(monkeypatch):
    monkeypatch.setattr(
        network_enrichment,
        "_whois_signals",
        lambda host: {
            "domain_age_days": None,
            "whois_available": False,
            "lookup_status": "timeout",
        },
    )
    monkeypatch.setattr(
        network_enrichment,
        "_tls_signals",
        lambda host: {
            "certificate_checked": False,
            "certificate_valid": False,
            "lookup_status": "timeout",
        },
    )
    raw = {
        "network_signals": {
            "enrichment_enabled": True,
            "whois": network_enrichment._whois_signals("example.com"),
            "tls": network_enrichment._tls_signals("example.com"),
            "dns": {},
            "reputation": {},
        }
    }

    explanation = _build_explanation(raw, "model")

    assert "website could not be reached for content verification" not in explanation


def test_network_explanation_lists_young_domain_and_invalid_certificate():
    raw = {
        "network_signals": {
            "whois": {"domain_age_days": 3},
            "tls": {"certificate_checked": True, "certificate_valid": False},
        }
    }

    explanation = _build_explanation(raw, "network_signal")

    assert "only 3 days old" in explanation
    assert "certificate is invalid" in explanation


def test_reputation_explanation_names_provider():
    raw = {
        "network_signals": {
            "reputation": {"reputation_provider": "URLhaus"}
        }
    }

    explanation = _build_explanation(raw, "reputation")

    assert "URLhaus" in explanation


def test_model_explanation_includes_available_network_checks():
    raw = {
        "explanation": "The model assigned a safe risk.",
        "network_signals": {
            "enrichment_enabled": True,
            "dns": {"dns_resolves": True, "nameserver_count": 2, "has_mx": False},
            "whois": {"domain_age_days": 120},
            "tls": {
                "certificate_checked": True,
                "certificate_valid": True,
                "certificate_days_remaining": 60,
            },
            "reputation": {
                "reputation_provider": "URLhaus",
                "reputation_hit": False,
                "lookup_status": "ok",
            },
        },
    }

    explanation = _build_explanation(raw, "model")

    assert "website address resolved successfully" in explanation
    assert "no known malicious report was found" in explanation


def test_fetched_page_signal_overrides_safe_model():
    result = apply_policy(
        "https://example.com",
        {
            "prediction": "benign",
            "phishing_probability": 0.0,
            "network_signals": {
                "http": {
                    "has_password_field": True,
                    "external_form_count": 1,
                    "cross_domain_redirect": True,
                    "suspicious_text_hits": 1,
                }
            },
        },
        [],
        [],
    )

    assert result["source"] == "fetched_page_signal"
    assert result["risk_level"] == "dangerous"


def test_unverified_site_cannot_be_marked_safe():
    result = apply_policy(
        "https://microsoft-login.compromisedsite.com",
        {
            "prediction": "benign",
            "phishing_probability": 0.003,
            "network_signals": {
                "enrichment_enabled": True,
                "dns": {"dns_resolves": False},
                "http": {"request_status": "unavailable"},
                "tls": {"certificate_checked": False},
                "whois": {"lookup_status": "timeout"},
                "reputation": {},
            },
        },
        [],
        [],
    )

    assert result["risk_level"] == "suspicious"
    assert result["source"] == "verification_incomplete"
    assert result["phishing_probability"] >= 0.3


def test_official_domain_remains_safe_when_page_fetch_times_out():
    result = apply_policy(
        "https://www.discord.com",
        {
            "prediction": "benign",
            "phishing_probability": 0.01,
            "high_confidence_signals": {"known_official_domain": True},
            "network_signals": {
                "enrichment_enabled": True,
                "dns": {"dns_resolves": True},
                "tls": {
                    "certificate_checked": True,
                    "certificate_valid": True,
                },
                "http": {
                    "request_status": "timeout",
                    "cross_domain_redirect": False,
                },
                "reputation": {"reputation_hit": False},
            },
        },
        [],
        [],
    )

    assert result["risk_level"] == "safe"
    assert result["source"] == "official_domain_registry"
    assert result["verification_status"] == "partial"


def test_brand_impersonation_overrides_safe_model():
    result = apply_policy(
        "https://ledger.unrelated-example.com",
        {
            "prediction": "benign",
            "phishing_probability": 0.01,
            "high_confidence_signals": {"brand_impersonation": True},
            "network_signals": {"enrichment_enabled": True},
        },
        [],
        [],
    )
    assert result["risk_level"] == "dangerous"
    assert result["source"] == "high_confidence_domain_signal"


def test_dns_mx_failure_does_not_skip_nameservers(monkeypatch):
    class Resolver:
        timeout = None
        lifetime = None

        def resolve(self, host, record_type):
            if record_type == "MX":
                raise RuntimeError("no MX record")
            return ["ns1.example.com", "ns2.example.com"]

    fake_resolver_module = type("DnsResolver", (), {"Resolver": Resolver})
    fake_dns_module = type("Dns", (), {"resolver": fake_resolver_module})
    monkeypatch.setitem(__import__("sys").modules, "dns", fake_dns_module)
    monkeypatch.setitem(
        __import__("sys").modules, "dns.resolver", fake_resolver_module
    )
    monkeypatch.setattr(network_enrichment.socket, "getaddrinfo", lambda *_: [])

    result = network_enrichment._dns_signals("example.com")

    assert result["has_mx"] is False
    assert result["nameserver_count"] == 2


def test_completed_http_check_is_not_hidden_by_slow_whois(monkeypatch):
    monkeypatch.setattr(
        network_enrichment,
        "_dns_signals",
        lambda host: {"dns_resolves": True},
    )
    monkeypatch.setattr(
        network_enrichment,
        "_whois_signals",
        lambda host: (__import__("time").sleep(0.2) or {"lookup_status": "ok"}),
    )
    monkeypatch.setattr(
        network_enrichment,
        "_urlhaus_reputation",
        lambda url: {"lookup_status": "ok", "reputation_hit": False},
    )
    monkeypatch.setattr(
        network_enrichment,
        "_http_signals",
        lambda url: {
            "request_status": "ok",
            "http_status": 200,
            "redirect_count": 0,
        },
    )
    monkeypatch.setattr(
        network_enrichment.config, "ENRICHMENT_TIMEOUT_SECONDS", 1
    )

    result = network_enrichment.enrich_url("https://example.com")

    assert result["http"]["request_status"] == "ok"


def test_http_timeout_is_not_reported_when_request_finishes_within_budget(
    monkeypatch,
):
    monkeypatch.setattr(
        network_enrichment.config, "ENRICHMENT_TIMEOUT_SECONDS", 5
    )
    monkeypatch.setattr(
        network_enrichment,
        "_http_signals",
        lambda url: {"request_status": "ok", "http_status": 403},
    )
    monkeypatch.setattr(
        network_enrichment,
        "_dns_signals",
        lambda host: {"dns_resolves": True},
    )
    monkeypatch.setattr(
        network_enrichment,
        "_whois_signals",
        lambda host: {"lookup_status": "timeout"},
    )
    monkeypatch.setattr(
        network_enrichment,
        "_tls_signals",
        lambda host: {
            "certificate_checked": True,
            "certificate_valid": True,
        },
    )
    monkeypatch.setattr(
        network_enrichment,
        "_urlhaus_reputation",
        lambda url: {"lookup_status": "ok", "reputation_hit": False},
    )

    result = network_enrichment.enrich_url("https://discord.com")

    assert result["http"]["request_status"] == "ok"


def test_model_explanation_is_preserved_for_model_source():
    raw = {
        "explanation": (
            "The model assigned a dangerous risk (97.0% phishing probability). "
            "Model contribution analysis shows that HTTPS scheme increased the score."
        ),
        "network_signals": {
            "enrichment_enabled": True,
            "dns": {"dns_resolves": True},
            "http": {"request_status": "ok", "http_status": 200},
            "tls": {"certificate_checked": True, "certificate_valid": True},
            "reputation": {"lookup_status": "ok", "reputation_provider": "URLhaus"},
        },
    }

    explanation = _build_explanation(raw, "model")

    assert "dangerous risk (97.0% phishing probability)" in explanation
    assert "HTTPS scheme increased the score" in explanation
