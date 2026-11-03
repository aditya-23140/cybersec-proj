// content.js — PhishGuard link click interceptor
// IMPORTANT: This script only reads link href attributes.
// It does NOT read page content, cookies, credentials, or any user data.

(function () {
  if (window.__phishguardLoaded) return;
  window.__phishguardLoaded = true;

  // Schemes to never intercept
  const SKIP_SCHEMES = /^(mailto:|tel:|javascript:|data:|#)/i;

  document.addEventListener('click', handleLinkClick, true);
  reportPageSignals();

  function reportPageSignals() {
    const pageUrl = window.location.href;
    if (!/^https?:\/\//i.test(pageUrl)) return;

    const pageHost = window.location.hostname;
    const privateHost = /^(localhost|.*\.local|.*\.internal|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|127\.\d+\.\d+\.\d+)$/.test(pageHost);
    const forms = Array.from(document.forms);
    const externalFormCount = forms.filter((form) => {
      try {
        const action = new URL(form.action || pageUrl, pageUrl);
        return action.hostname !== pageHost;
      } catch (_) {
        return false;
      }
    }).length;

    function sanitisedPageHtml() {
      const clone = document.documentElement.cloneNode(true);
      clone.querySelectorAll('input').forEach((input) => {
        input.removeAttribute('value');
        input.value = '';
      });
      clone.querySelectorAll('textarea').forEach((textarea) => {
        textarea.textContent = '';
        textarea.value = '';
      });
      return new XMLSerializer().serializeToString(clone).slice(0, 300000);
    }

    const pageSignals = {
      title_length: document.title.length,
      has_password_field: Boolean(document.querySelector('input[type="password"]')),
      external_form_count: externalFormCount,
      iframe_count: document.querySelectorAll('iframe').length,
      external_reference_count: Array.from(document.querySelectorAll('[src], [href]'))
        .filter((element) => {
          try {
            const value = element.src || element.href;
            return value && new URL(value, pageUrl).hostname !== pageHost;
          } catch (_) {
            return false;
          }
        }).length,
      suspicious_text_hits: (document.querySelector('main, article, h1, h2')?.innerText || '')
        .toLowerCase()
        .split(/\s+/)
        .filter((word) => /verify|urgent|suspend|password|wallet|billing/.test(word)).length,
      has_favicon: Boolean(document.querySelector('link[rel~="icon"]')),
      page_is_https: window.location.protocol === 'https:',
      page_html: sanitisedPageHtml(),
    };

    chrome.storage.sync.get({ allowlist: [] }, (settings) => {
      const allowlisted = settings.allowlist.some((domain) =>
        pageHost === domain || pageHost.endsWith(`.${domain}`));
      if (privateHost || allowlisted) return;
      chrome.runtime.sendMessage({
      type: 'PAGE_SIGNALS',
      url: pageUrl,
      pageSignals: { ...pageSignals, page_html: undefined },
      pageHtml: pageSignals.page_html,
      }, (response) => {
        if (chrome.runtime.lastError) return;
        if (response?.risk === 'dangerous') showPageWarning(response.explanation);
      });
    });
  }

  function showPageWarning(explanation) {
    if (document.getElementById('__phishguard_page_warning__')) return;
    const overlay = document.createElement('div');
    overlay.id = '__phishguard_page_warning__';
    overlay.style.cssText = [
      'position:fixed', 'inset:0', 'z-index:2147483647',
      'background:rgba(127,29,29,0.96)', 'color:white', 'padding:48px',
      'font:16px system-ui,sans-serif', 'text-align:center',
    ].join(';');
    const title = document.createElement('h1');
    title.textContent = 'PhishGuard: High-risk page detected';
    const message = document.createElement('p');
    message.textContent = explanation || 'This page contains high-risk phishing signals.';
    const dismiss = document.createElement('button');
    dismiss.textContent = 'Continue anyway';
    dismiss.style.cssText = 'padding:10px 18px;font-size:16px;cursor:pointer';
    dismiss.addEventListener('click', () => overlay.remove());
    overlay.append(title, message, dismiss);
    document.documentElement.appendChild(overlay);
  }

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
