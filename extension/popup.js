// popup.js — PhishGuard extension popup logic

const DEFAULT_BACKEND = 'http://127.0.0.1:8000';

const statusDot  = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const urlInput   = document.getElementById('url-input');
const checkBtn   = document.getElementById('check-btn');
const resultArea = document.getElementById('result-area');
const loading    = document.getElementById('loading');
const errorArea  = document.getElementById('error-area');
const settingsLink = document.getElementById('settings-link');

let backendUrl = DEFAULT_BACKEND;

// ── Init ────────────────────────────────────────────────────────────────────
async function init() {
  try {
    const stored = await chrome.storage.sync.get({ backendUrl: DEFAULT_BACKEND });
    backendUrl = stored.backendUrl || DEFAULT_BACKEND;
  } catch (_) {}
  await checkHealth();
}

// ── Health check ─────────────────────────────────────────────────────────────
async function checkHealth() {
  try {
    const res = await fetch(`${backendUrl}/api/v1/health`, { signal: AbortSignal.timeout(4000) });
    if (res.ok) {
      statusDot.className  = 'status-dot online';
      statusText.textContent = 'Backend connected';
    } else {
      throw new Error(`HTTP ${res.status}`);
    }
  } catch (_) {
    statusDot.className  = 'status-dot offline';
    statusText.textContent = 'Backend offline';
  }
}

// ── URL checker ───────────────────────────────────────────────────────────────
checkBtn.addEventListener('click', () => runCheck());
urlInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') runCheck(); });

async function runCheck() {
  const url = urlInput.value.trim();

  // Validate
  if (!url) {
    showError('Please enter a URL.');
    urlInput.className = 'url-input error';
    return;
  }
  if (!/^https?:\/\//i.test(url)) {
    showError('URL must start with http:// or https://');
    urlInput.className = 'url-input error';
    return;
  }

  urlInput.className = 'url-input';
  hideAll();
  loading.style.display = 'flex';
  checkBtn.disabled = true;

  try {
    const res = await fetch(`${backendUrl}/api/v1/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(10000),
    });

    loading.style.display = 'none';
    checkBtn.disabled = false;

    if (!res.ok) {
      showError(`Backend error: HTTP ${res.status}`);
      return;
    }

    const data = await res.json();
    renderResult(url, data);
  } catch (err) {
    loading.style.display = 'none';
    checkBtn.disabled = false;
    if (err.name === 'TimeoutError' || err.name === 'AbortError') {
      showError('Request timed out. Is the backend running?');
    } else {
      showError(`Could not reach backend: ${err.message}`);
    }
  }
}

// ── Render result ─────────────────────────────────────────────────────────────
function renderResult(url, data) {
  const risk = data.risk_level || 'unknown';
  const prob = typeof data.phishing_probability === 'number'
    ? (data.phishing_probability * 100).toFixed(1) + '%'
    : 'N/A';
  const explanation = data.explanation || '';
  const warnings    = Array.isArray(data.warnings) ? data.warnings : [];

  const card = document.createElement('div');
  card.className = 'result-card';

  // Header row: badge + probability
  const header = document.createElement('div');
  header.className = 'result-header';

  const badge = document.createElement('span');
  badge.className = `risk-badge ${risk}`;
  badge.textContent = risk.toUpperCase();

  const probEl = document.createElement('span');
  probEl.className = 'prob-display';
  probEl.textContent = prob;

  header.appendChild(badge);
  header.appendChild(probEl);
  card.appendChild(header);

  // URL (text only)
  const urlEl = document.createElement('p');
  urlEl.className = 'result-url';
  urlEl.textContent = url;
  card.appendChild(urlEl);

  // Explanation
  if (explanation) {
    const expEl = document.createElement('p');
    expEl.className = 'result-explanation';
    expEl.textContent = explanation;
    card.appendChild(expEl);
  }

  // Warnings
  if (warnings.length > 0) {
    const wList = document.createElement('ul');
    wList.className = 'result-warnings';
    warnings.forEach((w) => {
      const li = document.createElement('li');
      li.textContent = String(w);
      wList.appendChild(li);
    });
    card.appendChild(wList);
  }

  // Disclaimer
  const disc = document.createElement('p');
  disc.className = 'result-disclaimer';
  disc.textContent =
    'This combines URL and, when available, aggregate page-structure signals — not a guarantee. ' +
    'False positives and false negatives are possible.';
  card.appendChild(disc);

  resultArea.innerHTML = '';
  resultArea.appendChild(card);
  resultArea.style.display = 'block';
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function showError(msg) {
  hideAll();
  errorArea.textContent = msg;
  errorArea.style.display = 'block';
}

function hideAll() {
  resultArea.style.display = 'none';
  loading.style.display    = 'none';
  errorArea.style.display  = 'none';
}

// ── Settings link ─────────────────────────────────────────────────────────────
settingsLink.addEventListener('click', (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

// ── Start ─────────────────────────────────────────────────────────────────────
init();
