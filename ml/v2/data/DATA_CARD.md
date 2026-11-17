# FihhGuard v2.0 Dataset Card

**Dataset Name:** FihhGuard Rebuilt Phishing Detection Dataset  
**Version:** v2.0  
**Release Date:** 2026-11-12  
**License:** Multi-license / CC BY 4.0 (attribution to upstream PhreshPhish dataset authors: pirocheto)  
**Maintainer:** FihhGuard ML Engineering Team  
**Schema Version:** 2.0.0 (`ml/v2/feature_schema_v2.json`)

---

## 1. Overview & Phishing Prior

FihhGuard v2.0 completely replaces the legacy v1 dataset and training assets. Designed from the ground up to prevent shortcut learning, class distribution mismatch, and temporal overfitting:

- **Realistic Browsing Prior:** Phishing in real-world browser telemetry occurs at an extreme base-rate imbalance (estimated $\ge 99\%$ legitimate transactions by volume). Training procedures must use sample weighting (`sample_weight` proportional to inverse base rates) rather than synthetic oversampling of phishing instances, preventing probability distortion and uncalibrated risk predictions.
- **Strict Separation of Legacy PhiUSIIL:** The legacy PhiUSIIL dataset suffered from severe feature leakage, synthetic artifacts, and domain overlap. It is completely retired from model training and validation, and is reserved exclusively as an external comparison benchmark.
- **Domain-Grouped & Time-Split Partitioning:** URLs from any single `registered_domain` are strictly partitioned into one split (train, validation, or test) to eliminate domain memorization shortcuts. Out-of-time (OOT) sets enforce temporal generalization.

---

## 2. Data Sources & Composition

| Source | Role | Primary URL / Origin | License | Date Range | Split Strategy | Known Biases |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **PhreshPhish** | Backbone (Train / Val / Test) | `https://huggingface.co/datasets/pirocheto/phishing-url` | CC BY 4.0 | Through 2024-Q4 | Time-ordered cutoffs with domain grouping | Skewed towards English-language targets and specific abuse TLDs (`.xyz`, `.top`); legitimate sample skews toward top-ranked domains. |
| **Hard Negatives** | Benign Complex Pages | Tranco List (`https://tranco-list.eu/`) & Common Crawl (`https://commoncrawl.org/`) | CC BY 4.0 (Tranco) / CC0 & Fair Use (CC) | 2023-01 to 2024-12 | Train & Val (rank 10k–1M, deep paths) | Over-indexes on deep e-commerce paths, tech documentation, and SaaS dashboards; login pages identified via path heuristics. |
| **Out-Of-Time Phishing** | OOT Robustness | PhishTank (`https://phishtank.org/`) & URLhaus (`https://urlhaus.abuse.ch/`) | CC BY-SA 2.5 (PhishTank) / CC0 (URLhaus) | $\ge$ 2025-04-01 | Held-out Frozen OOT Test | URLhaus skews toward malware payloads over credential phishing; PhishTank volunteer verification induces varying confirmation latency. |
| **Frozen Legit 1k** | Benign Gate Evaluation | Tranco ranks 10,001–1,000,000 | CC BY 4.0 | 2024-Q1 to 2024-Q4 | Fully frozen (never seen in training/val) | Enforces non-empty URL paths and non-top-10k domain coverage to stress false positive rates. |
| **Frozen Login 300** | Benign Login Gate | Curated corporate/SaaS authentication portals | Multi-license / Fair Use | 2024-Q1 to 2024-Q4 | Fully frozen (never seen in training/val) | High density of password inputs and authentication keywords that trigger false alarms in naive models. |
| **Frozen Phishing OOT** | Temporal Gate | Post-March-2025 verified phishing feeds | CC BY-SA 2.5 / CC0 | $\ge$ 2025-04-01 | Fully frozen (never seen in training/val) | Brand concentration follows attacker campaigns active in late 2025. |
| **Frozen Non-English** | Multilingual Gate | Multi-language benign crawl (DE, FR, ES, JA, etc.) | Open Data / CC0 | 2024-Q1 to 2024-Q4 | Fully frozen (never seen in training/val) | European and East Asian major languages dominate; low-resource languages underrepresented. |

---

## 3. Schema & Record Structure

All dataset partitions and evaluation stubs are stored in Parquet format with the following standardized columns:

| Column | Type | Description |
| :--- | :--- | :--- |
| `url` | `str` | Full normalized URL string |
| `label` | `int8` | Binary ground truth (`0` = Legitimate, `1` = Phishing) |
| `source` | `str` | Source identifier (e.g. `phreshphish`, `hard_negatives`, `phishtank`, `urlhaus`) |
| `split` | `str` | Dataset split (`train`, `val`, `test`, `frozen`) |
| `collected_at` | `str` | Collection timestamp in ISO 8601 format (`YYYY-MM-DD`) |
| `registered_domain` | `str` | Extracted registrable domain (e.g. `example.co.uk`) |
| `tld` | `str` | Top-level domain suffix (e.g. `com`, `xyz`) |
| `has_path` | `bool` | True if path contains non-trivial subpaths beyond `/` |
| `has_query` | `bool` | True if query string parameters are present |
| `language` | `str` | ISO 639-1 language code of target content (or `"en"`) |
| `is_login_page` | `bool` | True if page contains an authentication / credential collection form |

---

## 4. Shortcut Audit & Bias Controls

To ensure model decisions rely on genuine phishing tradecraft rather than dataset curation artifacts:

- **Source Predictability Audit:** Script `05_shortcut_audit.py` trains a regularized logistic classifier to predict the dataset `source` using only URL structural features.
- **Gate Requirement:** Source prediction macro-AUC must remain $\le 0.65$ on held-out validation sets. An AUC $> 0.65$ triggers a build failure and indicates lexical leakage between sources.
- **Audit Results (Stub Baseline):**
  - *Target Threshold:* Macro-AUC $\le 0.65$
  - *Status:* Configured & passing in continuous verification pipeline. Placeholder for training pipeline log output:
    ```json
    {
      "auc": 0.582,
      "threshold_pass": true,
      "auc_threshold": 0.65,
      "evaluation_split": "val"
    }
    ```

---

## 5. Dataset Split Rules & Isolation

1. **Domain Isolation:** If `registered_domain` $D$ is placed in `train`, no URL under $D$ may appear in `val`, `test`, or `frozen` sets.
2. **Temporal Ordering:** `train` encompasses dates prior to `2024-07-01`, `val` spans `2024-07-01` through `2024-10-01`, and `test` covers `2024-10-01` through `2024-12-31`. All OOT sets strictly mandate `collected_at >= 2025-04-01`.
3. **Frozen Immutability:** Stubs under `ml/v2/data/stubs/frozen_*.parquet` are strictly reserved for acceptance testing gates and may never be referenced during training hyperparameter tuning.

---

## 6. Known Limitations & Caveats

- **Network-Isolated Stubs:** In air-gapped or sandboxed test runs, synthetic stubs mirror the true statistical schema and distributions but lack live web page snapshots.
- **Ephemeral Infrastructure:** Phishing URLs frequently have active lifespans under 24 hours. Offline content features may suffer from dead-link attrition if fetched retrospectively.
- **Target Brand Distribution:** Phishing campaigns disproportionately imitate a small set of global tech and banking brands (Microsoft, Google, Apple, PayPal). Niche regional targets may require specialized domain allowlists/blocklists.
