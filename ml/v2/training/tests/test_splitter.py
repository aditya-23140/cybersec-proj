"""
test_splitter.py — Tests for time_domain_split and leave_one_source_out_split.
"""

import pandas as pd
import pytest

from ml.v2.training.splitter import leave_one_source_out_split, time_domain_split


@pytest.fixture
def sample_dataset() -> pd.DataFrame:
    """Creates a sample DataFrame with time, domain, and source columns."""
    records = []
    # 10 distinct domains, timestamps from 2024-01-01 to 2024-01-20
    domains = [f"domain{i}.com" for i in range(10)]
    sources = ["phreshphish", "openphish", "tranco"]

    for day in range(1, 21):
        for d_idx, domain in enumerate(domains):
            records.append({
                "url": f"https://{domain}/path_{day}",
                "registered_domain": domain,
                "collected_at": f"2024-01-{day:02d}T10:00:00Z",
                "source": sources[d_idx % len(sources)],
                "label": d_idx % 2,
            })
    return pd.DataFrame(records)


def test_no_domain_leakage(sample_dataset: pd.DataFrame):
    """Assert train, val, and test splits have strictly disjoint domain sets."""
    train_idx, val_idx, test_idx = time_domain_split(
        sample_dataset,
        time_col="collected_at",
        domain_col="registered_domain",
        train_frac=0.70,
        val_frac=0.15,
    )

    train_domains = set(sample_dataset.loc[train_idx, "registered_domain"].dropna())
    val_domains = set(sample_dataset.loc[val_idx, "registered_domain"].dropna())
    test_domains = set(sample_dataset.loc[test_idx, "registered_domain"].dropna())

    # Disjointness checks
    assert train_domains.isdisjoint(val_domains), f"Overlap train-val: {train_domains & val_domains}"
    assert train_domains.isdisjoint(test_domains), f"Overlap train-test: {train_domains & test_domains}"
    assert val_domains.isdisjoint(test_domains), f"Overlap val-test: {val_domains & test_domains}"


def test_time_ordering_preserved(sample_dataset: pd.DataFrame):
    """Assert within each split, records preserve chronological ordering."""
    train_idx, val_idx, test_idx = time_domain_split(
        sample_dataset,
        time_col="collected_at",
        domain_col="registered_domain",
        train_frac=0.70,
        val_frac=0.15,
    )

    for split_name, idx in [("train", train_idx), ("val", val_idx), ("test", test_idx)]:
        if len(idx) > 1:
            times = sample_dataset.loc[idx, "collected_at"].tolist()
            assert times == sorted(times), f"Time order violated in {split_name} split"


def test_leave_one_source_out(sample_dataset: pd.DataFrame):
    """Assert leave_one_source_out holds out exactly the right source."""
    held_out = "openphish"
    train_idx, val_idx, test_idx = leave_one_source_out_split(
        sample_dataset,
        held_out_source=held_out,
        source_col="source",
        val_frac=0.20,
    )

    # Test split must contain ONLY the held_out source
    test_sources = sample_dataset.loc[test_idx, "source"].unique()
    assert list(test_sources) == [held_out], f"Unexpected test sources: {test_sources}"

    # Train and val splits must NOT contain the held_out source
    train_sources = sample_dataset.loc[train_idx, "source"].unique()
    val_sources = sample_dataset.loc[val_idx, "source"].unique()

    assert held_out not in train_sources, f"Held-out source found in train: {train_sources}"
    assert held_out not in val_sources, f"Held-out source found in val: {val_sources}"
    assert len(test_idx) + len(train_idx) + len(val_idx) == len(sample_dataset)
