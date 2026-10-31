"""
tests/test_features.py — Unit tests for feature_extractor.py.
"""
import sys
from pathlib import Path

# Ensure ml/ root is on path when running pytest from ml/
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from src.feature_extractor import (
    FEATURE_NAMES,
    FeatureVector,
    extract_features,
)


def test_feature_count_correct():
    fv = extract_features("https://example.com")
    assert len(fv.features) == len(FEATURE_NAMES)
    assert fv.feature_names == FEATURE_NAMES


def test_feature_names_match_constant():
    fv = extract_features("https://example.com")
    assert fv.feature_names == FEATURE_NAMES


def test_length_url():
    url = "https://example.com"
    fv = extract_features(url)
    idx = FEATURE_NAMES.index("length_url")
    assert fv.features[idx] == float(len(url))


def test_qty_dots_url():
    url = "https://a.b.c.example.com/path"
    fv = extract_features(url)
    idx = FEATURE_NAMES.index("qty_dots_url")
    assert fv.features[idx] == float(url.count("."))


def test_qty_hyphens_path():
    url = "https://example.com/my-page-with-hyphens"
    fv = extract_features(url)
    idx = FEATURE_NAMES.index("qty_hyphens_path")
    assert fv.features[idx] == 3.0


def test_no_hyphens_in_path():
    url = "https://example.com/simplepath"
    fv = extract_features(url)
    idx = FEATURE_NAMES.index("qty_hyphens_path")
    assert fv.features[idx] == 0.0


def test_subdomain_count_no_subdomains():
    fv = extract_features("https://example.com")
    idx = FEATURE_NAMES.index("subdomain_count")
    assert fv.features[idx] == 0.0


def test_subdomain_count_with_subdomains():
    fv = extract_features("https://sub1.sub2.example.com")
    idx = FEATURE_NAMES.index("subdomain_count")
    assert fv.features[idx] >= 2.0


def test_has_brand_keyword_positive():
    # "paypal" is a brand keyword
    fv = extract_features("http://paypal-secure-login.xyz/verify")
    idx = FEATURE_NAMES.index("has_brand_keyword")
    assert fv.features[idx] == 1.0


def test_has_brand_keyword_negative():
    fv = extract_features("https://randomsite12345.net/page")
    idx = FEATURE_NAMES.index("has_brand_keyword")
    assert fv.features[idx] == 0.0


def test_network_features_fallback_when_dns_disabled():
    """Without DNS, network features should use fallback values (not error)."""
    fv = extract_features("https://example.com", enable_dns=False)
    assert len(fv.features) == len(FEATURE_NAMES)
    # Missing features list should include the three network features
    assert "qty_nameservers" in fv.missing_features
    assert "is_spf_domain" in fv.missing_features
    assert "time_domain_activation" in fv.missing_features


def test_determinism():
    """Same URL should always produce the same feature vector."""
    url = "https://www.example.co.uk/path?q=1"
    fv1 = extract_features(url)
    fv2 = extract_features(url)
    assert fv1.features == fv2.features


def test_ip_address_host():
    """IP addresses should parse without error."""
    fv = extract_features("http://192.168.1.1/login")
    assert len(fv.features) == len(FEATURE_NAMES)
    # subdomain_count for IP should be 0
    idx = FEATURE_NAMES.index("subdomain_count")
    assert fv.features[idx] == 0.0


def test_url_without_scheme_gets_https():
    """URLs without a scheme should get https:// prepended."""
    fv = extract_features("example.com/path")
    assert len(fv.features) == len(FEATURE_NAMES)


def test_invalid_scheme_raises():
    with pytest.raises(ValueError, match="Unsupported URL scheme"):
        extract_features("javascript:alert(1)")


def test_data_uri_raises():
    with pytest.raises(ValueError, match="Unsupported URL scheme"):
        extract_features("data:text/html,<h1>hi</h1>")


def test_empty_url_raises():
    with pytest.raises(ValueError):
        extract_features("")


def test_feature_vector_is_all_floats():
    fv = extract_features("https://login-secure-paypal.xyz/verify?token=abc")
    for val in fv.features:
        assert isinstance(val, float), f"Expected float, got {type(val)} for value {val}"


def test_url_with_port():
    """URLs with explicit ports should not break parsing."""
    fv = extract_features("http://example.com:8080/path")
    assert len(fv.features) == len(FEATURE_NAMES)


def test_url_with_query_and_fragment():
    fv = extract_features("https://example.com/path?foo=bar&baz=qux#section")
    assert len(fv.features) == len(FEATURE_NAMES)


def test_idn_url():
    """Internationalized domain names should not crash."""
    fv = extract_features("https://münchen.de/page")
    assert len(fv.features) == len(FEATURE_NAMES)


def test_brand_lookalike_positive():
    fv = extract_features("https://www.paypa1.com")
    assert fv.features[FEATURE_NAMES.index("brand_lookalike")] == 1.0


def test_exact_brand_domain_is_not_lookalike():
    fv = extract_features("https://www.google.com")
    assert fv.features[FEATURE_NAMES.index("brand_lookalike")] == 0.0
