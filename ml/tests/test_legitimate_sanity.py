import phishing_hybrid as ph
import pandas as pd


def test_legitimate_sanity_phishing_rate_is_below_two_percent():
    detector = ph.HybridDetector.load("artifacts/hybrid.joblib")
    urls = pd.read_csv("data/sanity_legitimate_nonpopular.csv")["url"].tolist()
    assert len(urls) >= 300
    results = [detector.analyze(url, fetch=False) for url in urls]
    phishing_rate = sum(item["verdict"] == "phishing" for item in results) / len(results)
    assert phishing_rate <= 0.02


def test_hosting_subdomains_are_not_popular_domain_shortcuts():
    detector = ph.HybridDetector.load("artifacts/hybrid.joblib")
    result = detector.analyze("https://user.github.io", fetch=False)
    assert result.get("trusted_domain") is not True


def test_allowlist_is_capped_at_top_ten_thousand_and_rank_stays_available():
    top = ph.TopDomains([f"site{i}.example" for i in range(1, 10001)] + ["tail.example"])
    assert top.is_exact_popular("site9999.example")
    assert top.is_exact_popular("site10000.example")
    assert not top.is_exact_popular("tail.example")
    assert ph.top_features("https://tail.example/account", top)[-1] > 0
