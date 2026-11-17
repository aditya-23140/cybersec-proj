# PhishGuard — URL Phishing Detection and Prevention System

> Academic cybersecurity project based on:  
> Misiek & Hyla, "XGBoost-Based URL Phishing Detection Method With Cross-Dataset Validation," IEEE Access, 2026.

---

## Architecture

```
ml/          ← XGBoost training pipeline + feature extractor
backend/     ← FastAPI API server (loads ml/ model)
extension/   ← Chrome Manifest V3 extension
frontend/    ← Next.js web application
```

Both the **extension** and the **web app** call the **same** backend prediction endpoint (`POST /api/v1/predict`). No model logic lives in the clients.

### Hybrid model diagnostics

The backend loads `ml/v2/artifacts/bundle.pkl.gz` by default. Scans operate
in URL-only mode by default because server-side page fetching defaults to OFF
(`ENABLE_PAGE_FETCH=false`). When `ENABLE_PAGE_FETCH=true` or when `page_html`
is provided (e.g. if the user explicitly opts into extension DOM upload),
inference runs in hybrid `url+content` mode. Server-side fetches enforce strict
SSRF protections (pinning connections to validated non-private IPs, manual redirect
re-validation, and TLS verification). A failed or disabled fetch remains visible
as `fetch_error` in the response instead of being silently treated as a full
scan. Exact registered popular domains are checked against the top domains list
to identify brand impersonation attempts.

Run the ML test suite with:

```bash
pytest ml/v2/tests/ ml/v2/features/tests/ ml/v2/training/tests/ -v
```

---

## Prerequisites

- Python 3.10+
- Node.js 18+ and npm
- Google Chrome (for extension)

---

## 1. ML Pipeline — Train the Model

```bash
cd ml

# Install Python dependencies
pip install -r requirements.txt

# Train the v2 model bundle
python -m ml.v2.training.cli train

# Run ML tests
pytest v2/tests/ v2/features/tests/ v2/training/tests/ -v
```

**Artifacts produced** in `ml/v2/artifacts/`:
- `bundle.pkl.gz` — trained LightGBM model, Platt calibrator, and feature schema
- `evaluation_report.json` — measured metrics across validation and test splits

### Standalone model CLI

The ML v2 package provides an all-in-one CLI for training, evaluation, and inference:

```bash
# Evaluate against quality gates
python -m ml.v2.training.cli evaluate

# Run CLI prediction on a URL
python -m ml.v2.training.cli predict "https://example.com"
```

---

## 2. Backend — FastAPI Server

```bash
cd backend

# Install dependencies
pip install fastapi uvicorn "python-jose[cryptography]" "passlib[bcrypt]" pydantic pytest httpx pytest-asyncio

# Copy and edit environment
cp .env.example .env

# Start the server (from backend/ directory)
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Set `JWT_SECRET_KEY` in `.env` to a strong random value (at least 32 characters, required).
The server will refuse to start if it is missing or too short. Generate one using:
`python -c "import secrets; print(secrets.token_hex(32))"`. Tokens issued before
changing this value are invalid and require signing in again.

**On first start:**
- Creates `phishing.db` with full schema
- Prints a one-time admin password to the console — save it

**Verify model loaded:**
```bash
curl http://127.0.0.1:8000/api/v1/health
# Expect: {"status":"ok","model_loaded":true,...}
```

**Test a URL:**
```bash
curl -X POST http://127.0.0.1:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -d '{"url":"https://paypal-secure-login.xyz/verify"}'
```

**Run backend tests:**
```bash
cd backend
python -m pytest tests/ -v
```

---

## 3. Chrome Extension

1. Open Chrome → `chrome://extensions`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `extension/` directory

**First use:**
- Click the 🛡️ PhishGuard icon in the toolbar
- The popup shows backend connection status
- Paste a URL into the popup to test manually
- Click any link on any webpage — if suspicious/dangerous, a warning page appears

**Settings:**
- Click the extension icon → settings gear → change backend URL if needed
- The settings page includes auto-scan, sensitivity, theme-ready privacy controls,
  and a first-run onboarding walkthrough.

**What the extension protects:**
- ✅ HTTP/HTTPS link clicks on ordinary web pages
- ❌ Address bar navigation (cannot be intercepted by content scripts)
- ❌ New tab links opened with Ctrl+Click (browser handles before script)
- ❌ Browser-internal pages (chrome://, file://)
- ❌ Redirects after initial navigation

---

## 4. Web Application — Next.js Frontend

```bash
cd frontend

# Install dependencies
npm install

# Copy env (already pre-configured for local backend)
cp .env.local.example .env.local

# Start development server
npm run dev
```

Open http://localhost:3000

The web app uses the Next.js App Router. The shared visual language lives in
[`design/tokens.css`](./design/tokens.css), which is imported by both web and
extension styles. It defines Paper/Ink neutrals, Electric Lime brand actions,
verdict colours, sticker shadows, radii, and light/dark theme variables.
Mascot, verdict, risk-meter, reason-list, scan-mode, and URL-input components
are shared within `frontend/app/components/`.

**Pages:**
| URL | Feature |
|---|---|
| `/` | URL Checker (main feature) |
| `/dashboard` | Statistics from real DB records |
| `/history` | Your scan history (login required) |
| `/lists` | Allow/block list management (login required) |
| `/forum` | Community forum (login required to post) |
| `/education` | Phishing prevention guide |
| `/login` | Login |
| `/register` | Register |

The extension can be loaded as an unpacked MV3 extension from `extension/`.
Its popup is designed for a 360px toolbar surface, caches the latest result
locally for instant opening, and sends only the existing URL/page-signal
payloads to the configured backend.

---

## 5. End-to-End Demo Procedure

1. **Start backend:** `cd backend && uvicorn main:app --port 8000`
2. **Start frontend:** `cd frontend && npm run dev`
3. **Load extension** in Chrome (see step 3 above)
4. Open http://localhost:3000
5. Check a URL: paste `http://paypal-secure-login.xyz/verify?token=abc123`
   - Should show: **Dangerous** or **Suspicious** risk level
6. Check a safe URL: `https://github.com`
   - Should show: **Safe**
7. Register an account at http://localhost:3000/register
8. Log in and check http://localhost:3000/history — your scans appear
9. In Chrome, navigate to any webpage and click a link — see the "Checking…" overlay
10. For a demo warning: paste `http://paypal-verify-secure.xyz` into the extension popup

---

## 6. API Reference

Base URL: `http://127.0.0.1:8000`

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/health` | No | Health check |
| GET | `/api/v1/model-info` | No | Model version + thresholds |
| GET | `/api/v1/stats` | No | Aggregate scan statistics |
| POST | `/api/v1/predict` | No | **Analyse a URL** |
| POST | `/api/v1/auth/register` | No | Create account |
| POST | `/api/v1/auth/login` | No | Get JWT token |
| POST | `/api/v1/auth/logout` | No | (client-side token drop) |
| GET | `/api/v1/auth/me` | JWT | Current user |
| GET | `/api/v1/history` | JWT | Your scan history |
| GET/POST | `/api/v1/allowlist` | JWT | Manage allowlist |
| DELETE | `/api/v1/allowlist/{id}` | JWT | Remove allowlist entry |
| GET/POST | `/api/v1/blocklist` | JWT | Manage blocklist |
| DELETE | `/api/v1/blocklist/{id}` | JWT | Remove blocklist entry |
| GET/POST | `/api/v1/forum/posts` | JWT | List/create forum posts |
| GET | `/api/v1/forum/posts/{id}` | JWT | Get post |
| GET/POST | `/api/v1/forum/posts/{id}/replies` | JWT | List/add replies |

---

## 7. Features and Paper Alignment

### 12 Model Features (Misiek & Hyla, 2026)

| Feature | Computed from |
|---|---|---|
| `length_url` | URL string | Always available |
| `qty_dots_url` | URL string | Always available |
| `qty_hyphens_path` | URL path | Always available |
| `subdomain_count` | URL hostname | Always available |
| `has_brand_keyword` | URL hostname | Always available |
| `hostname_hyphen_count`, `hostname_digit_count` | URL hostname | Always available |
| `brand_lookalike` | URL hostname | Always available |
| `suspicious_path_keyword` | URL path/query | Always available |
| `is_domain_ip`, `has_obfuscation`, `digit_ratio_url` | URL/dataset fields | Always available |

The trained model contains no synthetic DNS/WHOIS fallback values. Prediction runs
as pure local ML inference with optional bounded page fetching for hybrid scanning.
External 3rd-party network enrichment (DNS, WHOIS, URLhaus) has been retired in favor
of pure ML scoring, with `network_signals` preserved for API compatibility.

The product uses a hybrid decision architecture. The URL model produces a
calibrated `url_model_score` as supporting evidence, while the final assessment
is produced by the evidence policy. Reputation hits, credential-harvesting page
signals, and brand lookalikes take precedence over model output.

### Risk Thresholds

Thresholds are selected on the validation set during model evaluation. See `ml/v2/evaluation_report.json`.

---

## 8. Known Limitations

- **Coverage limits:** The hybrid model analyses URL patterns and, when supplied, a bounded sanitized DOM snapshot. None of these independently verifies website ownership or page safety.
- **False positives:** Legitimate sites with brand keywords or unusual URL structures may be flagged.
- **Cross-dataset degradation:** As shown in research, performance on URLs from different sources/time periods is typically lower than in-distribution test performance.
- **No real-time updates:** The model is static post-training. New phishing patterns require retraining.
- **Extension scope:** The extension only intercepts link clicks via content scripts, not address-bar navigation or all redirect chains.

---

## 9. Security Notes

- Passwords are hashed with bcrypt (never stored in plaintext)
- JWTs expire after 24 hours
- CORS restricted to `http://localhost:3000` by default
- Bounded SSRF-safe page fetch can be disabled via `ENABLE_PAGE_FETCH=false`
- Forum input is stored as plain text and escaped on render
- User data is isolated server-side; one user cannot access another's history/lists

---

## 10. Project Structure

```
cybersec-proj/
├── ml/                    # ML pipeline & v2 architecture
│   ├── v2/
│   │   ├── features/      # Lexical, brand, content, redirect feature extractors
│   │   ├── training/      # Dataset loaders, splitter, train, evaluate, bundle CLI
│   │   ├── serving/       # Fast detector inference engine
│   │   ├── data/          # Split manifest, data card, ingestion scripts
│   │   └── artifacts/     # Model bundle (bundle.pkl.gz)
│   └── tests/
├── backend/               # FastAPI server
│   ├── main.py
│   ├── routes/            # predict, auth, history, lists, forum, stats
│   ├── services/          # predictor, risk_policy, page_fetcher, auth_service
│   └── tests/
├── extension/             # Chrome MV3 extension
│   ├── manifest.json
│   ├── background.js      # Service worker
│   ├── content.js         # Link click interceptor
│   ├── warning.html/js    # Interstitial warning page
│   └── popup.html/js      # Manual URL checker
└── frontend/              # Next.js web app (App Router)
    ├── app/               # Next.js App Router pages
    └── lib/api.js         # API client
```
