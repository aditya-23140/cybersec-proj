// content.js — PhishGuard link click interceptor
// IMPORTANT: This script only reads link href attributes.
// It does NOT read page content, cookies, credentials, or any user data.

(function () {
  if (window.__phishguardLoaded) return;
  window.__phishguardLoaded = true;

  // Schemes to never intercept
  const SKIP_SCHEMES = /^(mailto:|tel:|javascript:|data:|#)/i;

  document.addEventListener('click', handleLinkClick, true);

  function handleLinkClick(event) {
    const link = event.target.closest('a[href]');
    if (!link) return;

    const href = link.href;

    // Skip non-http(s) links
    if (!href || !href.match(/^https?:\/\//i)) return;

    // Skip fragment-only, mailto, tel, javascript, data links
    if (SKIP_SCHEMES.test(link.getAttribute('href') || '')) return;

    // Skip if this is the same page (just a hash navigation)
    try {
      const linkUrl = new URL(href);
      const currentUrl = new URL(window.location.href);
      if (
        linkUrl.hostname === currentUrl.hostname &&
        linkUrl.pathname === currentUrl.pathname &&
        linkUrl.hash !== ''
      ) {
        return;
      }
    } catch (_) {
      // If URL parsing fails, skip interception
      return;
    }

    event.preventDefault();
    event.stopImmediatePropagation();

    // Show a brief "Checking..." tooltip near the link
    const overlay = showCheckingOverlay(link);

    chrome.runtime.sendMessage({ type: 'CHECK_URL', url: href }, (response) => {
      removeOverlay(overlay);

      if (chrome.runtime.lastError) {
        // Background service worker unavailable — navigate anyway
        console.warn('[PhishGuard] Background unavailable:', chrome.runtime.lastError.message);
        window.location.href = href;
        return;
      }

      if (response && response.action === 'navigate') {
        window.location.href = href;
      }
      // If action === 'warn', background has already opened the warning tab — do nothing here
    });
  }

  function showCheckingOverlay(link) {
    const overlay = document.createElement('div');
    overlay.id = '__phishguard_overlay__';
    overlay.style.cssText = [
      'position:fixed',
      'bottom:16px',
      'left:50%',
      'transform:translateX(-50%)',
      'background:rgba(30,41,59,0.95)',
      'color:#e2e8f0',
      'padding:8px 18px',
      'border-radius:8px',
      'font-size:13px',
      'font-family:system-ui,sans-serif',
      'z-index:2147483647',
      'box-shadow:0 4px 16px rgba(0,0,0,0.4)',
      'pointer-events:none',
      'letter-spacing:0.02em',
    ].join(';');
    overlay.textContent = '🔍 PhishGuard: Checking link safety…';
    document.body.appendChild(overlay);
    return overlay;
  }

  function removeOverlay(overlay) {
    if (overlay && overlay.parentNode) {
      overlay.parentNode.removeChild(overlay);
    }
  }
})();
