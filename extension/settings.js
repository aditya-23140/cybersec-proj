// settings.js — PhishGuard settings page logic

const DEFAULT_BACKEND_URL = 'http://127.0.0.1:8000';

const backendInput = document.getElementById('backend-url');
const saveBtn      = document.getElementById('btn-save');
const feedback     = document.getElementById('feedback');
const autoScan = document.getElementById('auto-scan');
const themeSelect = document.getElementById('theme-select');

// ── Load saved settings on open ───────────────────────────────────────────────
async function loadSettings() {
  try {
    const stored = await chrome.storage.sync.get({ backendUrl: DEFAULT_BACKEND_URL, autoScan: true, sensitivity: 'balanced', theme: 'system' });
    backendInput.value = stored.backendUrl || DEFAULT_BACKEND_URL;
    autoScan.checked = stored.autoScan !== false;
    const sensitivity = document.querySelector(`input[name="sensitivity"][value="${stored.sensitivity}"]`);
    if (sensitivity) sensitivity.checked = true;
    themeSelect.value = stored.theme || 'system';
    applyTheme(themeSelect.value);
  } catch (err) {
    showFeedback('Failed to load settings: ' + err.message, false);
  }
}

// ── Save ──────────────────────────────────────────────────────────────────────
saveBtn.addEventListener('click', async () => {
  const value = backendInput.value.trim();

  if (!value) {
    showFeedback('Backend URL cannot be empty.', false);
    return;
  }

  // Basic URL validation
  try {
    const parsed = new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      showFeedback('URL must use http:// or https:// protocol.', false);
      return;
    }
  } catch (_) {
    showFeedback('Invalid URL format. Example: http://127.0.0.1:8000', false);
    return;
  }

  try {
    await chrome.storage.sync.set({
      backendUrl: value,
      autoScan: autoScan.checked,
      sensitivity: document.querySelector('input[name="sensitivity"]:checked')?.value || 'balanced',
      theme: themeSelect.value,
    });

    showFeedback('✓ Settings saved successfully.', true);
  } catch (err) {
    showFeedback('Failed to save settings: ' + err.message, false);
  }
});

themeSelect.addEventListener('change', () => applyTheme(themeSelect.value));

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme === 'system'
    ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
    : theme;
}

// ── Feedback helper ───────────────────────────────────────────────────────────
function showFeedback(msg, success) {
  feedback.textContent = msg;
  feedback.className   = success ? 'success' : 'error';
  setTimeout(() => {
    feedback.textContent = '';
    feedback.className   = '';
  }, 4000);
}

// ── Init ──────────────────────────────────────────────────────────────────────
loadSettings();
