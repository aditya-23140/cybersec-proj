# FihhGuard v2 — Kaggle Cloud Training Guide

This guide explains how to train the FihhGuard v2 model on real PhreshPhish data (CC BY 4.0) using Kaggle's free cloud infrastructure without burdening your local machine.

---

## Step 1: Open Kaggle
1. Go to [kaggle.com](https://www.kaggle.com) and log in.
2. Click **Create** -> **New Notebook**.

---

## Step 2: Enable Internet Access (Crucial)
1. On the right-hand settings panel in your Kaggle notebook:
2. Look under **Notebook options**.
3. Toggle **Internet** to **ON**.  
   *(This allows Kaggle to stream the dataset directly from Hugging Face).*

---

## Step 3: Run the Training Script
Copy the entire contents of [`ml/v2/training/kaggle_train_phreshphish.py`](file:///home/immortal_soul/immortal_soul/Coding/cybersec-proj/ml/v2/training/kaggle_train_phreshphish.py) into the first cell of the notebook and click **Run** (or `Shift + Enter`).

### What the script does automatically:
1. **Installs dependencies:** `datasets`, `huggingface_hub`, `xgboost`, `scikit-learn`, `joblib`.
2. **Streams real PhreshPhish data:** Ingests real phishing and benign HTML-URL pairs (50,000 training, 10,000 test benchmark).
3. **Applies anti-shortcut safeguards:** Computes length-balanced sample weights and isolates registered domains across splits.
4. **Trains XGBoost + LR baseline:** Uses GroupKFold cross-validation.
5. **Calibrates on realistic prior:** Applies Isotonic Regression weighted to realistic web browsing prior (~2% phishing).
6. **Validates all Acceptance Gates:** Computes Gate 1 (FPR), Gate 2 (Recall), Gate 3 (AUC gap), and Gate 4 (ECE).
7. **Exports deployable bundle:** Generates `bundle.pkl.gz` in `/kaggle/working/`.

---

## Step 4: Download the Model & Place in Repo
1. Once the notebook finishes, go to the right sidebar under **Output** (`/kaggle/working`).
2. Download `bundle.pkl.gz`.
3. Move `bundle.pkl.gz` into your local repo at:
   ```bash
   ml/v2/artifacts/bundle.pkl.gz
   ```

---

## Step 5: Start & Verify Backend
Once `bundle.pkl.gz` is placed into `ml/v2/artifacts/bundle.pkl.gz`, start the backend:
```bash
uvicorn backend.main:app --reload
```
Check model status:
```bash
curl http://localhost:8000/api/v1/model-info
```
The backend will immediately load the bundle, show `loaded: true`, and serve live predictions with calibrated risk levels and feature explanations.
