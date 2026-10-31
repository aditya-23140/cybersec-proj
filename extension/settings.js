// settings.js — PhishGuard settings page logic

const DEFAULT_BACKEND_URL = 'http://127.0.0.1:8000';

const backendInput = document.getElementById('backend-url');
const saveBtn      = document.getElementById('btn-save');
const resetBtn     = document.getElementById('btn-reset');
const feedback     = document.getElementById('feedback');

// ── Load saved settings on open ───────────────────────────────────────────────
async function loadSettings() {
  try {
    const stored = await chrome.storage.sync.get({ backendUrl: DEFAULT_BACKEND_URL });
    backendInput.value = stored.backendUrl || DEFAULT_BACKEND_URL;
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
    await chrome.storage.sync.set({ backendUrl: value });
    showFeedback('✓ Settings saved successfully.', true);
  } catch (err) {
    showFeedback('Failed to save settings: ' + err.message, false);
  }
});

// ── Reset ─────────────────────────────────────────────────────────────────────
resetBtn.addEventListener('click', async () => {
  backendInput.value = DEFAULT_BACKEND_URL;
  try {
    await chrome.storage.sync.set({ backendUrl: DEFAULT_BACKEND_URL });
    showFeedback('✓ Reset to default: ' + DEFAULT_BACKEND_URL, true);
  } catch (err) {
    showFeedback('Failed to reset: ' + err.message, false);
  }
});

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
