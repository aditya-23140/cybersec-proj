"""
test_brand.py — Unit tests for brand.py
"""

from __future__ import annotations

import unittest
from ml.v2.features.brand import extract_brand_features


class TestBrand(unittest.TestCase):

    def test_exact_brand_domain(self):
        url = "https://paypal.com/signin"
        feats = extract_brand_features(url)
        self.assertEqual(feats["registered_domain_matches_brand"], 1.0)
        self.assertEqual(feats["brand_edit_distance_min"], 0.0)

    def test_typosquat(self):
        url = "https://paypa1.com/login"
        feats = extract_brand_features(url)
        # 'paypa1' is 1 edit distance from 'paypal'
        self.assertLessEqual(feats["brand_edit_distance_min"], 0.2)
        self.assertEqual(feats["registered_domain_matches_brand"], 0.0)

    def test_clean_unrelated_domain(self):
        url = "https://acme-brick-factory-supply.org/catalog"
        feats = extract_brand_features(url)
        # Distance to popular brands should be high (closer to 1.0)
        self.assertGreaterEqual(feats["brand_edit_distance_min"], 0.5)
        self.assertEqual(feats["registered_domain_matches_brand"], 0.0)

    def test_homoglyph_in_hostname(self):
        # Cyrillic 'о' in 'gооgle.com'
        url = "http://g\u043e\u043egle.com/login"
        feats = extract_brand_features(url)
        self.assertGreater(feats["brand_homoglyph_score"], 0.0)

        # Lookalike numbers: 'micr0s0ft.com'
        url2 = "http://micr0s0ft.com/account"
        feats2 = extract_brand_features(url2)
        self.assertGreater(feats2["brand_homoglyph_score"], 0.0)

    def test_brand_keyword_in_subdomain(self):
        url = "https://paypal.evil-phish.com/verify"
        feats = extract_brand_features(url)
        self.assertEqual(feats["brand_keyword_in_subdomain"], 1.0)
        self.assertEqual(feats["registered_domain_matches_brand"], 0.0)

    def test_brand_keyword_in_path(self):
        url = "https://suspicious-site.tk/paypal/account/signin"
        feats = extract_brand_features(url)
        self.assertEqual(feats["brand_keyword_in_path"], 1.0)

    def test_page_title_mismatch(self):
        # Brand claimed in title is PayPal, but domain is evil.com
        url = "https://evil.com/signin"
        feats = extract_brand_features(url, page_title="Log in to your PayPal account")
        self.assertEqual(feats["known_brand_in_title"], 1.0)
        self.assertEqual(feats["page_claimed_brand_mismatch"], 1.0)

        # Matching title and domain
        feats_legit = extract_brand_features("https://paypal.com/signin", page_title="PayPal Login")
        self.assertEqual(feats_legit["page_claimed_brand_mismatch"], 0.0)

    def test_none_url(self):
        # Must not crash
        feats = extract_brand_features(None)  # type: ignore
        self.assertIsInstance(feats, dict)


if __name__ == "__main__":
    unittest.main()
