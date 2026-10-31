// warning.js — PhishGuard warning page logic
// Reads ONLY from URLSearchParams — never from any external source on this page.

(function () {
  const params = new URLSearchParams(window.location.search);

  // Safely extract each param
  const destUrl     = params.get('url')         || '';
  const risk        = params.get('risk')         || 'unknown';
  const probRaw     = params.get('prob')         || '';
  const explanation = params.get('explanation')  || '';
  const warningsRaw = params.get('warnings')     || '[]';
  const error       = params.get('error')        || '';

  // --- Render destination URL (text only, never as a link innerHTML) ---
  const urlEl = document.getElementById('dest-url');
  urlEl.textContent = destUrl || '(unknown URL)';

  // --- Risk badge ---
  const badge = document.getElementById('risk-badge');
  badge.textContent = risk.toUpperCase();
  badge.className = 'risk-badge ' + (['dangerous', 'suspicious', 'safe', 'unknown'].includes(risk) ? risk : 'unknown');

  // --- Headline & icon ---
  const headline  = document.getElementById('headline');
  const iconArea  = document.getElementById('icon-area');
  const container = document.getElementById('warning-container');

  if (risk === 'dangerous') {
    iconArea.textContent  = '🚨';
    headline.textContent  = 'Warning: This Link May Be Dangerous';
    container.style.borderTop = '4px solid #ef4444';
  } else if (risk === 'suspicious') {
    iconArea.textContent  = '⚠️';
    headline.textContent  = 'Suspicious Link Detected';
    container.style.borderTop = '4px solid #f97316';
  } else {
    iconArea.textContent  = '❓';
    headline.textContent  = 'Link Safety Unknown';
    container.style.borderTop = '4px solid #64748b';
  }

  // --- Phishing probability ---
  const probRow   = document.getElementById('prob-row');
  const probValue = document.getElementById('prob-value');
  const probNum   = parseFloat(probRaw);
  if (!isNaN(probNum) && probRaw !== '' && probNum > 0) {
    probValue.textContent = (probNum * 100).toFixed(1) + '%';
  } else if (risk === 'unknown') {
    probRow.style.display = 'none';
  } else {
    probValue.textContent = 'N/A';
  }

  // --- Explanation ---
  if (explanation) {
    const expBox  = document.getElementById('explanation-box');
    const expText = document.getElementById('explanation-text');
    expText.textContent = explanation;   // textContent, not innerHTML — safe
    expBox.style.display = 'block';
  }

  // --- Warnings list ---
  let warnings = [];
  try {
    warnings = JSON.parse(warningsRaw);
  } catch (_) { warnings = []; }

  if (Array.isArray(warnings) && warnings.length > 0) {
    const list = document.getElementById('warnings-list');
    warnings.forEach((w) => {
      const li = document.createElement('li');
      li.textContent = String(w);  // safe text
      list.appendChild(li);
    });
    list.style.display = 'block';
  }

  // --- Error display ---
  if (error) {
    const errorBox  = document.getElementById('error-box');
    const errorText = document.getElementById('error-text');
    const messages  = {
      timeout:             '⏱ The safety check timed out (backend took too long). The link has not been verified.',
      service_unavailable: '🔌 The PhishGuard backend is not reachable. Start the backend service and try again.',
    };
    errorText.textContent = messages[error] || `An error occurred: ${error}`;
    errorBox.style.display = 'block';
  }

  // --- Buttons ---
  document.getElementById('btn-back').addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  });

  document.getElementById('btn-continue').addEventListener('click', () => {
    if (destUrl) {
      // Validate the URL before navigating
      try {
        const parsed = new URL(destUrl);
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
          window.location.href = destUrl;
          return;
        }
      } catch (_) {}
    }
    // If URL is invalid or unsafe scheme, just close/go back
    window.close();
  });
})();
