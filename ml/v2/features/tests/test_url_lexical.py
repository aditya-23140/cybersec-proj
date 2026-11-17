"""
test_url_lexical.py — Unit tests for url_lexical.py
"""

from __future__ import annotations

import unittest
from ml.v2.features.url_lexical import extract_url_lexical


class TestUrlLexical(unittest.TestCase):

    def test_normal_url(self):
        url = "https://paypal-login.example.com/account/verify?token=abc"
        feats = extract_url_lexical(url)
        self.assertIsInstance(feats, dict)
        self.assertEqual(feats["url_length"], len(url))
        self.assertEqual(feats["hostname_length"], len("paypal-login.example.com"))
        self.assertEqual(feats["path_length"], len("/account/verify"))
        self.assertEqual(feats["query_length"], len("token=abc"))
        self.assertEqual(feats["subdomain_depth"], 1.0)  # paypal-login.example.com has 3 labels -> 3-2 = 1
        self.assertEqual(feats["path_token_count"], 2.0)
        self.assertEqual(feats["has_ip_host"], 0.0)
        self.assertEqual(feats["shortener_flag"], 0.0)

    def test_ip_host_url(self):
        url = "http://192.168.1.1/phish"
        feats = extract_url_lexical(url)
        self.assertEqual(feats["has_ip_host"], 1.0)
        self.assertEqual(feats["subdomain_depth"], 0.0)
        self.assertGreater(feats["digit_ratio_url"], 0.0)

    def test_idn_url(self):
        # 'pаypal.com' using cyrillic small letter 'а' (U+0430)
        url = "http://p\u0430ypal.com"
        feats = extract_url_lexical(url)
        self.assertGreater(feats["idn_homograph_score"], 0.0)

    def test_url_shortener(self):
        url = "https://bit.ly/abc123"
        feats = extract_url_lexical(url)
        self.assertEqual(feats["shortener_flag"], 1.0)

    def test_shared_hosting(self):
        url = "https://my-store.web.app/shop/checkout"
        feats = extract_url_lexical(url)
        self.assertEqual(feats["shared_hosting_flag"], 1.0)

    def test_empty_url(self):
        # Must not crash
        feats = extract_url_lexical("")
        self.assertIsInstance(feats, dict)
        self.assertEqual(feats["url_length"], 0.0)

    def test_none_url(self):
        # Must not crash
        feats = extract_url_lexical(None)  # type: ignore
        self.assertIsInstance(feats, dict)

    def test_entropy_real_url(self):
        url = "https://paypal-login.suspicious.tk/verify/account?token=abc123"
        feats = extract_url_lexical(url)
        self.assertGreater(feats["url_entropy"], 0.0)
        self.assertGreater(feats["hostname_entropy"], 0.0)
        self.assertGreater(feats["path_entropy"], 0.0)
        self.assertEqual(feats["tld_risk_score"], 1.0)  # .tk is high risk

    def test_digit_ratio_ip_url(self):
        url = "http://10.0.0.1/login"
        feats = extract_url_lexical(url)
        self.assertGreater(feats["digit_ratio_url"], 0.0)

    def test_no_scheme_feature(self):
        # Rule 3: Never use scheme (http/https) as a feature
        feats = extract_url_lexical("https://example.com")
        self.assertNotIn("is_https", feats)
        self.assertNotIn("has_https", feats)
        self.assertNotIn("scheme", feats)
        self.assertNotIn("protocol", feats)


if __name__ == "__main__":
    unittest.main()
