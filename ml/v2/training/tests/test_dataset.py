"""
test_dataset.py — Tests for PhishDataset loading and feature group dropout.
"""

from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from ml.v2.training.dataset import PhishDataset, _MockExtractor


@pytest.fixture
def temp_parquet_file(tmp_path: Path) -> Path:
    """Creates a temporary parquet file mirroring stub data schema."""
    data = {
        "url": [
            "https://example.com/login",
            "https://test-bank-secure.xyz/verify",
            "https://normal-site.org/about",
            "https://phish-attack.top/account",
        ],
        "label": [0, 1, 0, 1],
        "source": ["phreshphish", "phreshphish", "tranco", "openphish"],
        "split": ["train", "train", "train", "train"],
        "collected_at": ["2024-01-01", "2024-01-02", "2024-01-03", "2024-01-04"],
        "registered_domain": ["example.com", "test-bank-secure.xyz", "normal-site.org", "phish-attack.top"],
        "tld": ["com", "xyz", "org", "top"],
        "has_path": [True, True, True, True],
        "has_query": [False, False, False, False],
        "language": ["en", "en", "en", "en"],
        "is_login_page": [True, True, False, True],
    }
    df = pd.DataFrame(data)
    file_path = tmp_path / "sample.parquet"
    df.to_parquet(file_path, index=False)
    return file_path


def test_load_dataset(temp_parquet_file: Path):
    """Test loading data via PhishDataset."""
    extractor = _MockExtractor()
    ds = PhishDataset([str(temp_parquet_file)], extractor=extractor)
    X, y, meta_df = ds.load()

    assert X.shape[0] == 4
    assert X.shape[1] == extractor.feature_count
    assert len(y) == 4
    assert list(y) == [0, 1, 0, 1]
    assert len(meta_df) == 4
    assert "available_groups" in meta_df.columns
    # Ensure no NaNs exist in X
    assert not np.isnan(X).any()


def test_feature_group_dropout():
    """Test that feature group dropout correctly zeros specified columns."""
    extractor = _MockExtractor()
    ds = PhishDataset([], extractor=extractor)

    n_samples = 20
    n_features = extractor.feature_count
    # Initialize X with all ones
    X = np.ones((n_samples, n_features), dtype=np.float32)

    page_content_indices = ds._get_group_indices("page_content")
    assert len(page_content_indices) > 0

    # With drop_prob = 1.0, all page_content columns should become 0.0
    X_dropped = ds.apply_feature_group_dropout(
        X, groups=["page_content"], drop_prob=1.0, seed=42
    )

    # All page_content indices must be strictly 0.0
    assert np.all(X_dropped[:, page_content_indices] == 0.0)

    # Columns outside page_content must remain unchanged (1.0)
    other_indices = [i for i in range(n_features) if i not in page_content_indices]
    assert np.all(X_dropped[:, other_indices] == 1.0)

    # With drop_prob = 0.0, nothing is dropped
    X_unchanged = ds.apply_feature_group_dropout(
        X, groups=["page_content"], drop_prob=0.0, seed=42
    )
    assert np.all(X_unchanged == 1.0)
