// background.js — PhishGuard Service Worker
// Handles URL safety checks by calling the local ML backend.

const DEFAULT_BACKEND_URL = 'http://127.0.0.1:8000';
const CHECK_TIMEOUT_MS = 5000;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'CHECK_URL') {
    handleCheckUrl(message.url, sender, sendResponse);
    return true; // Keep channel open for async response
  }
});

async function handleCheckUrl(url, sender, sendResponse) {
  let backendUrl = DEFAULT_BACKEND_URL;

  try {
    const stored = await chrome.storage.sync.get({ backendUrl: DEFAULT_BACKEND_URL });
    backendUrl = stored.backendUrl || DEFAULT_BACKEND_URL;
  } catch (_) {
    // Use default if storage read fails
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), CHECK_TIMEOUT_MS);

  try {
    const res = await fetch(`${backendUrl}/api/v1/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!res.ok) {
      throw new Error(`Backend returned HTTP ${res.status}`);
    }

    const data = await res.json();

    if (!data.risk_level || !['safe', 'suspicious', 'dangerous'].includes(data.risk_level)) {
      throw new Error('Invalid or missing risk_level in backend response');
    }

    if (data.risk_level === 'safe') {
      sendResponse({ action: 'navigate' });
    } else {
      const warningUrl =
        chrome.runtime.getURL('warning.html') +
        '?url=' + encodeURIComponent(url) +
        '&risk=' + encodeURIComponent(data.risk_level) +
        '&prob=' + encodeURIComponent(data.phishing_probability ?? '') +
        '&explanation=' + encodeURIComponent(data.explanation || '') +
        '&warnings=' + encodeURIComponent(JSON.stringify(data.warnings || []));

      await chrome.tabs.create({ url: warningUrl });
      sendResponse({ action: 'warn' });
    }
  } catch (err) {
    clearTimeout(timeoutId);
    const isTimeout = err.name === 'AbortError';
    const errorType = isTimeout ? 'timeout' : 'service_unavailable';

    console.warn('[PhishGuard] Check failed:', err.message);

    const warningUrl =
      chrome.runtime.getURL('warning.html') +
      '?url=' + encodeURIComponent(url) +
      '&risk=unknown' +
      '&prob=0' +
      '&error=' + encodeURIComponent(errorType);

    try {
      await chrome.tabs.create({ url: warningUrl });
    } catch (_) {
      // If we can't open a tab, just navigate anyway as a fallback
    }
    sendResponse({ action: 'warn' });
  }
}
