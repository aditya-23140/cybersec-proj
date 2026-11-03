const DEFAULT_BACKEND = 'http://127.0.0.1:8000';
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const urlInput = document.getElementById('url-input');
const checkBtn = document.getElementById('check-btn');
const resultArea = document.getElementById('result-area');
const loading = document.getElementById('loading');
const errorArea = document.getElementById('error-area');
const settingsLink = document.getElementById('settings-link');
const allowLink = document.getElementById('allow-link');
let backendUrl = DEFAULT_BACKEND;

const reasons = {
  c_form_action_external: 'the login form sends data elsewhere',
  c_has_password: 'the page asks for a password',
  t_lookalike_dist: 'the domain looks like a popular brand',
  t_brand_in_domain: 'a brand appears in an unrelated domain',
  subdomain_len: 'the subdomain is unusually long',
};

async function init() {
  try {
    const stored = await chrome.storage.sync.get({ backendUrl: DEFAULT_BACKEND, theme: 'system' });
    backendUrl = stored.backendUrl || DEFAULT_BACKEND;
    document.documentElement.dataset.theme = stored.theme === 'system'
      ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
      : stored.theme;
  } catch (_) {}
  try {
    const cached = await chrome.storage.local.get({ lastResult: null });
    if (cached.lastResult) renderResult(cached.lastResult.url, cached.lastResult);
  } catch (_) {}
  await checkHealth();
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs[0]?.url && /^https?:\/\//i.test(tabs[0].url)) {
      urlInput.value = tabs[0].url;
      allowLink.dataset.domain = new URL(tabs[0].url).hostname;
    }
  } catch (_) {}
}

async function checkHealth() {
  try {
    const res = await fetch(`${backendUrl}/api/v1/health`, { signal: AbortSignal.timeout(4000) });
    if (!res.ok) throw new Error();
    statusDot.className = 'status-dot online'; statusText.textContent = 'backend connected';
  } catch (_) { statusDot.className = 'status-dot offline'; statusText.textContent = 'backend offline'; }
}

checkBtn.addEventListener('click', runCheck);
urlInput.addEventListener('keydown', (event) => { if (event.key === 'Enter') runCheck(); });
allowLink.addEventListener('click', async () => {
  const domain = allowLink.dataset.domain;
  if (!domain) return;
  const stored = await chrome.storage.sync.get({ allowlist: [] });
  if (!stored.allowlist.includes(domain)) stored.allowlist.push(domain);
  await chrome.storage.sync.set({ allowlist: stored.allowlist });
  allowLink.textContent = 'site allowed';
});
settingsLink.addEventListener('click', (event) => { event.preventDefault(); chrome.runtime.openOptionsPage(); });

async function runCheck() {
  const url = urlInput.value.trim();
  if (!/^https?:\/\/.+/i.test(url)) { showError('drop in a full http:// or https:// link.'); return; }
  hideAll(); loading.style.display = 'flex'; checkBtn.disabled = true;
  try {
    const res = await fetch(`${backendUrl}/api/v1/predict`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }), signal: AbortSignal.timeout(10000) });
    if (!res.ok) throw new Error(`backend error: HTTP ${res.status}`);
    const data = await res.json();
    await chrome.storage.local.set({ lastResult: data });
    renderResult(url, data);
  } catch (error) { showError(error.name === 'TimeoutError' ? 'that took too long. try again?' : error.message); }
  finally { loading.style.display = 'none'; checkBtn.disabled = false; }
}

function mascot(mood) {
  const expression = mood === 'safe' ? 'chill' : mood === 'suspicious' ? 'sidee' : mood === 'dangerous' ? 'alarmed' : 'unknown';
  const eye = expression === 'sleepy'
    ? '<path d="M14 29q3 3 6 0" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>'
    : `<circle cx="17" cy="29" r="${expression === 'alarmed' ? 4 : 3}" fill="currentColor"/><circle cx="${expression === 'sidee' ? 15.8 : 16}" cy="28" r="1" fill="var(--paper)"/>`;
  const expressionPaths = {
    chill: '<path d="M10 36q3 2 6 0" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>',
    sidee: '<path d="M12 24 21 25M10 36h5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>',
    alarmed: '<circle cx="12" cy="36" r="1.8" stroke="currentColor" stroke-width="1.6"/><path d="m8 22-2-3m6 2v-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>',
    unknown: '<path d="M10 36h5M22 24q0-4 3-4t3 2q0 2-3 3v1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="25" cy="29" r=".7" fill="currentColor"/>',
  };
  return `<svg class="fihh" viewBox="0 0 64 64" fill="none" role="img" aria-label="${expression} Fihh"><path d="M44 32 60 20q-2 12 0 24Z" fill="var(--accent)" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><ellipse cx="28" cy="32" rx="19" ry="14" fill="var(--accent)" stroke="currentColor" stroke-width="2"/><path d="M26 38q4 10 12 6-4-4-6-8Z" fill="var(--accent)" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>${eye}${expressionPaths[expression]}</svg>`;
}

function renderResult(url, data) {
  const risk = data.risk_level || 'unknown';
  const label = risk === 'dangerous' ? 'phishing' : risk;
  const message = risk === 'safe' ? 'looks clean. go forth and scroll.' : risk === 'suspicious' ? "hmm, this one's giving sketchy." : risk === 'dangerous' ? 'nope. this site is fishing for your info.' : "couldn't read this link. don't trust it blindly.";
  const probability = Math.round((Number(data.phishing_probability) || 0) * 100);
  const list = (data.evidence_summary?.hybrid_reasons || data.reasons || []).slice(0, 3).map((item) => `<li>${reasons[item.feature] || String(item.feature).replaceAll('_', ' ')}</li>`).join('');
  const fetchNote = data.fetch_error ? `<p class="fetch-note">link-only scan: ${data.fetch_error}</p>` : '';
  resultArea.innerHTML = `<article class="result-card ${risk}"><div class="verdict-row">${mascot(risk)}<div><div class="verdict">${label}</div><p class="message">${message}</p></div></div><p class="url-text">${url}</p><div class="meter-row"><div class="meter ${risk}"><span style="width:${probability}%"></span></div><strong>${probability}%</strong></div><span class="scan-mode">${data.model_mode === 'url+content' ? 'full scan' : 'link-only scan'}</span>${fetchNote}<div class="reasons"><h3>why we think so</h3><ul>${list || '<li>no single signal did all the talking</li>'}</ul></div></article>`;
  resultArea.style.display = 'block';
}
function showError(message) { hideAll(); errorArea.textContent = message; errorArea.style.display = 'block'; }
function hideAll() { resultArea.style.display = 'none'; loading.style.display = 'none'; errorArea.style.display = 'none'; }
init();
