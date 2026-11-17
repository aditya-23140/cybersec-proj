# PhishGuard — Next Steps and Execution Guide

> **Current Status:** All active operations are paused per user instruction.  
> **Environment State:** Python ML and backend dependencies (`xgboost`, `scikit-learn`, `fastapi`, `uvicorn`, `passlib`, `python-jose`, `pydantic`, etc.) have been installed successfully.

---

## Quick Reference: Remaining Tasks to Complete

Follow these exact steps when you are ready to resume:

### Step 1: Run ML Unit Tests
Verify feature extraction, data preprocessing, and bundle logic:
```bash
pytest ml/v2/tests/ ml/v2/features/tests/ ml/v2/training/tests/ -v
```

### Step 2: Train the Model Artifact
Train the v2 model bundle or evaluate gates:
```bash
# Train model bundle
python -m ml.v2.training.cli train

# Or evaluate against quality gates
python -m ml.v2.training.cli evaluate
```
*Verification:* Ensure `ml/v2/artifacts/bundle.pkl.gz` exists and is non-empty.

### Step 3: Run Backend Unit & Integration Tests
Verify API routes, risk policy, database persistence, and authentication:
```bash
cd /home/immortal_soul/immortal_soul/Coding/cybersec-proj/backend
python3 -m pytest tests/ -v
```

### Step 4: Install Frontend Dependencies & Build
Install Node dependencies for the Next.js frontend:
```bash
cd /home/immortal_soul/immortal_soul/Coding/cybersec-proj/frontend
npm install
npm run build
```

### Step 5: Start the Backend and Frontend Services
In Terminal 1 (Backend):
```bash
cd /home/immortal_soul/immortal_soul/Coding/cybersec-proj/backend
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
*(Note: On first startup, `admin` user is initialized and its temporary generated password is printed in the terminal).*

In Terminal 2 (Web Frontend):
```bash
cd /home/immortal_soul/immortal_soul/Coding/cybersec-proj/frontend
npm run dev
```
Visit web app at: `http://localhost:3000`  
API Swagger Docs at: `http://127.0.0.1:8000/docs`

### Step 6: Load Chrome MV3 Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle in upper right).
3. Click **Load unpacked**.
4. Select the folder: `/home/immortal_soul/immortal_soul/Coding/cybersec-proj/extension`.
5. Click extension icon to test live URL inspection, or click links on any web page to see real-time phishing warning interstitials.

---
*All background tasks and automated subagents are currently halted.*
