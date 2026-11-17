# FihhGuard v2 Rebuild: Swarm Worktree Merge Plan & Inventory

## 1. Overview
The FihhGuard phishing detection model rebuild was partitioned across 5 swarm workers using isolated worktrees sharing the underlying repository object database. Each worker developed its designated phase in its worktree. This document inventories all files, branches, uncommitted changes, untracked artifacts, and git-ignored binaries before consolidating onto the integration branch `rebuild-model`.

---

## 2. Worker Worktree Inventory

### Worker: Phase 0 (`phase0`)
- **Role:** Legacy Model Retirement
- **Branch / Worktree:** `swarm-phase0-5e823ec6`
- **Path:** `/home/immortal_soul/.gemini/antigravity-cli/worktrees/93ae7424-d27f-48fd-8e0f-d7dcce0d6b35/swarm-phase0-5e823ec6`
- **Base Commit:** `9b08c9c` (tagged `legacy-model-final`)
- **Files Modified (tracked):**
  - `README.md` (documented `legacy-model-final` tag)
  - `backend/.env.example` (cleaned legacy env vars)
  - `backend/config.py` (removed legacy `HYBRID_MODEL_FILE`, set `MODEL_VERSION = "2.0.0-dev"`)
  - `backend/services/predictor.py` (replaced legacy hybrid/predict imports with clean 503 stub)
  - `frontend/lib/api.js` (cleaned endpoints)
- **Files Deleted (tracked):**
  - `backend/tests/test_fp_fn_regression.py`
  - `ml/config.py`, `ml/data_pipeline.py`, `ml/phishing_hybrid.py`, `ml/phishing_model.py`
  - `ml/src/__init__.py`, `ml/src/data_loader.py`, `ml/src/data_validation.py`, `ml/src/evaluate.py`, `ml/src/feature_extractor.py`, `ml/src/model_registry.py`, `ml/src/predict.py`, `ml/src/preprocessing.py`, `ml/src/train.py`
  - `ml/tests/test_data_sources.py`, `ml/tests/test_features.py`, `ml/tests/test_legitimate_sanity.py`, `ml/tests/test_openphish_loader.py`, `ml/tests/test_prediction.py`, `ml/tests/test_training.py`
  - `ml/data/phiusiil.csv`
  - `ml/artifacts/*` (all old joblib, ubj, json files)
  - `ml/reports/*` (all old reports)
- **Non-git / Archived Artifacts:**
  - Archived to `/archive/artifacts_legacy/`: `hybrid.joblib`, `hybrid-content.joblib`, `model.json`, `model.ubj`, `threshold_config.json`, `calibration.json`, `eval_results.json`, `metadata.json`, `feature_schema.json`
  - Archived to `/archive/`: `config.py`, `data_pipeline.py`, `phishing_hybrid.py`, `phishing_model.py`, `phiusiil.csv`

---

### Worker: Phase 1 (`phase1-data`)
- **Role:** Dataset Pipeline & Data Card
- **Branch / Worktree:** `swarm-phase1-data-8b54b95a`
- **Path:** `/home/immortal_soul/.gemini/antigravity-cli/worktrees/93ae7424-d27f-48fd-8e0f-d7dcce0d6b35/swarm-phase1-data-8b54b95a`
- **Base Commit:** `9b08c9c`
- **Files Added / Untracked:**
  - `ml/v2/feature_schema_v2.json` (67 features across 5 groups: url_lexical [24], brand [8], reputation [14], page_content [16], redirect [5])
  - `ml/v2/audit_result.json` (shortcut audit baseline)
  - `ml/v2/data/DATA_CARD.md` (PhreshPhish attribution CC BY 4.0, Tranco/CC hard negatives, bias & limit notes)
  - `ml/v2/data/split_manifest.json` (manifest of time-ordered domain-split sets)
  - `ml/v2/data/scripts/01_fetch_phreshphish.py`
  - `ml/v2/data/scripts/02_fetch_hard_negatives.py`
  - `ml/v2/data/scripts/03_fetch_out_of_time.py`
  - `ml/v2/data/scripts/04_build_frozen_sets.py`
  - `ml/v2/data/scripts/05_shortcut_audit.py`
  - `ml/v2/data/scripts/06_merge_and_split.py`
  - `ml/v2/data/scripts/generate_stubs.py`
- **Non-git / Binary Datasets (Parquet stubs):**
  - `ml/v2/data/stubs/phreshphish_train.parquet` (200 rows)
  - `ml/v2/data/stubs/phreshphish_val.parquet` (50 rows)
  - `ml/v2/data/stubs/phreshphish_test.parquet` (30 rows)
  - `ml/v2/data/stubs/hard_negatives.parquet` (100 rows)
  - `ml/v2/data/stubs/out_of_time_phishing.parquet` (50 rows)
  - `ml/v2/data/stubs/frozen_legit_1k.parquet` (100 rows)
  - `ml/v2/data/stubs/frozen_login_300.parquet` (50 rows)
  - `ml/v2/data/stubs/frozen_phishing_oot.parquet` (50 rows)
  - `ml/v2/data/stubs/frozen_noneng.parquet` (50 rows)

---

### Worker: Phase 2 (`phase2-features`)
- **Role:** Pure, Deterministic Feature Engineering
- **Branch / Worktree:** `swarm-phase2-features-c610c54f`
- **Path:** `/home/immortal_soul/.gemini/antigravity-cli/worktrees/93ae7424-d27f-48fd-8e0f-d7dcce0d6b35/swarm-phase2-features-c610c54f`
- **Base Commit:** `9b08c9c`
- **Files Added / Untracked:**
  - `ml/v2/features/__init__.py`
  - `ml/v2/features/schema.py` (FeatureSchema validator)
  - `ml/v2/features/url_lexical.py` (24 lexical features, no http/https scheme feature)
  - `ml/v2/features/brand.py` (8 brand impersonation / homoglyph features)
  - `ml/v2/features/reputation.py` (14 reputation features; graceful missing/NaN)
  - `ml/v2/features/page_content.py` (16 content features; stdlib html.parser)
  - `ml/v2/features/redirect.py` (5 redirect chain features)
  - `ml/v2/features/extractor.py` (FeatureExtractor orchestrator supporting modes `url-only`, `url+reputation`, `url+content`, `full`)
  - `ml/v2/features/tests/__init__.py`
  - `ml/v2/features/tests/test_url_lexical.py`
  - `ml/v2/features/tests/test_brand.py`
  - `ml/v2/features/tests/test_extractor.py` (23 unit tests, 100% passing)

---

### Worker: Phase 3 (`phase3-training`)
- **Role:** Training Pipeline, Calibrator, Evaluator, and Model Bundle
- **Branch / Worktree:** `swarm-phase3-training-eefa34ba`
- **Path:** `/home/immortal_soul/.gemini/antigravity-cli/worktrees/93ae7424-d27f-48fd-8e0f-d7dcce0d6b35/swarm-phase3-training-eefa34ba`
- **Base Commit:** `9b08c9c`
- **Files Added / Untracked:**
  - `ml/v2/training/__init__.py`
  - `ml/v2/training/dataset.py` (PhishDataset with group dropout)
  - `ml/v2/training/splitter.py` (time_domain_split and leave_one_source_out_split)
  - `ml/v2/training/train.py` (XGBoost + GroupKFold CV + LogisticRegression baseline)
  - `ml/v2/training/calibrate.py` (Isotonic regression reweighted to realistic prior)
  - `ml/v2/training/evaluate.py` (gate metrics calculation, slice metrics, SHAP explanations)
  - `ml/v2/training/hard_negative.py` (active negative mining loop)
  - `ml/v2/training/bundle.py` (ModelBundle single-file artifact container)
  - `ml/v2/training/cli.py` (train/evaluate/predict CLI entrypoints)
  - `ml/v2/training/tests/__init__.py`
  - `ml/v2/training/tests/test_splitter.py`
  - `ml/v2/training/tests/test_dataset.py`
  - `ml/v2/training/tests/test_bundle.py` (9 unit tests, 100% passing)
  - `ml/v2/setup.py` (console scripts registration)
- **Non-git / Model Artifacts:**
  - `ml/v2/artifacts/bundle.pkl.gz` (16,414 bytes)
  - `ml/artifacts/xgboost_model.joblib` (321 KB)
  - `ml/artifacts/logistic_regression_baseline.joblib`
  - `ml/artifacts/calibration_bundle.joblib`
  - `ml/artifacts/model_bundle.pkl.gz`
  - `ml/artifacts/training_report.json`
  - `ml/reports/evaluation_report.json`

---

### Worker: Phase 4 (`phase4-serving`)
- **Role:** Serving Layer, API Integration, and Acceptance Gate Regression
- **Branch / Worktree:** `swarm-phase4-serving-6f657708`
- **Path:** `/home/immortal_soul/.gemini/antigravity-cli/worktrees/93ae7424-d27f-48fd-8e0f-d7dcce0d6b35/swarm-phase4-serving-6f657708`
- **Base Commit:** `9b08c9c`
- **Files Added / Untracked:**
  - `ml/v2/serving/__init__.py`
  - `ml/v2/serving/detector.py` (Detector with 3-layer architecture: threat-intel -> allowlist -> model)
  - `ml/v2/serving/shadow_eval.py` (shadow logging, drift checking, feedback loop)
  - `ml/v2/tests/__init__.py`
  - `ml/v2/tests/conftest.py`
  - `ml/v2/tests/test_gates_regression.py` (Regression suite for Gates 1–5 and Gate 7)
  - `backend/tests/test_predict_new.py` (5 tests for 503, allowlist override, blocklist override, 422)
- **Files Modified (tracked):**
  - `backend/config.py` (configured `ML_BUNDLE_PATH`)
  - `backend/main.py` (updated `/health` and `/model-info`)
  - `backend/schemas.py` (added `groups_missing`, `schema_version`, `training_cutoff`, `model_status`, `model_available`)
  - `backend/services/predictor.py` (integrated Detector with fallback, error details, and status reporting)
  - `backend/routes/predict.py` (populated new fields on PredictResponse)

---

## 3. Dependency & Integration Order

The integration order respects component dependencies:
1. **Retirement & Base Cleaning (Phase 0):** Archive legacy artifacts, remove deprecated files from `ml/` and `backend/tests/`.
2. **Dataset & Schema (Phase 1):** Add `ml/v2/data/` scripts, `DATA_CARD.md`, and `feature_schema_v2.json`.
3. **Features (Phase 2):** Add `ml/v2/features/` modules and unit tests.
4. **Training & Model Bundle (Phase 3):** Add `ml/v2/training/`, bundle definition, and training artifacts in `ml/v2/artifacts/`.
5. **Serving & Backend (Phase 4):** Add `ml/v2/serving/detector.py`, update `backend/services/predictor.py`, `backend/routes/predict.py`, `backend/config.py`, `backend/schemas.py`.
6. **Tests & Regression:** Add `ml/v2/tests/test_gates_regression.py` and `backend/tests/test_predict_new.py`.

---

## 4. Conflict Analysis & Resolution Strategy

1. **`backend/config.py`:**
   - *Phase 0:* Removed `HYBRID_MODEL_FILE` and `HYBRID_FETCH_ENABLED`.
   - *Phase 4:* Replaced `ML_ARTIFACTS_DIR` with `ML_BUNDLE_PATH`.
   - *Resolution:* Path resolved relative to repo root (`Path(__file__).resolve().parents[1] / "ml" / "v2" / "artifacts" / "bundle.pkl.gz"`), added `ALLOW_UNGATED_MODEL` flag.

2. **`backend/services/predictor.py`:**
   - *Phase 0:* Created 503 stub.
   - *Phase 4:* Connected to `ml.v2.serving.detector.Detector`.
   - *Resolution:* Detector integration preserved; if bundle or Detector is absent, sets `_model_loaded = False` and logs detailed exception without crashing. Allows allowlist/blocklist layers to operate even when model is unavailable.

3. **`ml/v2/feature_schema_v2.json`:**
   - Present in both Phase 1 and Phase 2. Both schemas specify the identical 67 features and 5 feature groups.
   - *Resolution:* Canonical schema verified against `ml/v2/features/schema.py`.

4. **`ml/v2/serving/detector.py` bundle loading:**
   - *Issue:* `detector.py` attempted `pickle.load` on `bundle.pkl.gz`, but `ModelBundle.save()` compresses using `joblib`.
   - *Resolution:* Updated `_load_bundle` in `detector.py` to support `joblib.load(gz_f)` and fallback to `pickle.load(gz_f)`, and accept `schema_version` prefixed with `"2"`.
