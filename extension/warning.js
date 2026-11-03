// warning.js — PhishGuard warning page logic
// Reads ONLY from URLSearchParams — never from any external source on this page.

(function () {
  const params = new URLSearchParams(window.location.search);

  // Safely extract each param
  const destUrl = params.get("url") || "";
  const risk = params.get("risk") || "unknown";
  const probRaw = params.get("prob") || "";
  const explanation = params.get("explanation") || "";
  const warningsRaw = params.get("warnings") || "[]";
  const error = params.get("error") || "";

  // --- Render destination URL (text only, never as a link innerHTML) ---
  const urlEl = document.getElementById("dest-url");
  urlEl.textContent = destUrl || "(unknown URL)";

  // --- Risk badge ---
  const badge = document.getElementById("risk-badge");
  badge.textContent = risk.toUpperCase();
  badge.className =
    "risk-badge " +
    (["dangerous", "suspicious", "safe", "unknown"].includes(risk)
      ? risk
      : "unknown");

  // --- Headline & icon ---
  const headline = document.getElementById("headline");
  const iconArea = document.getElementById("icon-area");
  const container = document.getElementById("warning-container");

  if (risk === "dangerous") {
    iconArea.innerHTML = mascot("alarmed");
    headline.textContent = "wait. this link looks dangerous.";
  } else if (risk === "suspicious") {
    iconArea.innerHTML = mascot("sidee");
    headline.textContent = "hmm. this one's giving sketchy.";
  } else {
    iconArea.innerHTML = mascot("unknown");
    headline.textContent = "couldn't read this link.";
  }

  function mascot(mood) {
    const expression =
      mood === "alarmed" || mood === "sidee" ? mood : "unknown";
    const eye = `<circle cx="17" cy="29" r="${expression === "alarmed" ? 4 : 3}" fill="currentColor"/><circle cx="${expression === "sidee" ? 15.8 : 16}" cy="28" r="1" fill="var(--paper)"/>`;
    const face =
      expression === "alarmed"
        ? '<circle cx="12" cy="36" r="1.8" stroke="currentColor" stroke-width="1.6"/><path d="m8 22-2-3m6 2v-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>'
        : '<path d="M12 24 21 25M10 36h5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>';
    return `<svg class="fihh-warning" viewBox="0 0 64 64" fill="none" role="img" aria-label="${expression} Fihh"><path d="M44 32 60 20q-2 12 0 24Z" fill="var(--accent)" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><ellipse cx="28" cy="32" rx="19" ry="14" fill="var(--accent)" stroke="currentColor" stroke-width="2"/><path d="M26 38q4 10 12 6-4-4-6-8Z" fill="var(--accent)" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>${eye}${face}</svg>`;
  }

  // --- Phishing probability ---
  const probRow = document.getElementById("prob-row");
  const probValue = document.getElementById("prob-value");
  const probNum = parseFloat(probRaw);
  if (!isNaN(probNum) && probRaw !== "" && probNum > 0) {
    probValue.textContent = (probNum * 100).toFixed(1) + "%";
  } else if (risk === "unknown") {
    probRow.style.display = "none";
  } else {
    probValue.textContent = "N/A";
  }

  // --- Explanation ---
  if (explanation) {
    const expBox = document.getElementById("explanation-box");
    const expText = document.getElementById("explanation-text");
    expText.textContent = explanation; // textContent, not innerHTML — safe
    expBox.style.display = "block";
  }

  // --- Warnings list ---
  let warnings = [];
  try {
    warnings = JSON.parse(warningsRaw);
  } catch (_) {
    warnings = [];
  }

  if (Array.isArray(warnings) && warnings.length > 0) {
    const list = document.getElementById("warnings-list");
    warnings.forEach((w) => {
      const li = document.createElement("li");
      li.textContent = String(w); // safe text
      list.appendChild(li);
    });
    list.style.display = "block";
  }

  // --- Error display ---
  if (error) {
    const errorBox = document.getElementById("error-box");
    const errorText = document.getElementById("error-text");
    const messages = {
      timeout:
        "⏱ The safety check timed out (backend took too long). The link has not been verified.",
      service_unavailable:
        "🔌 The PhishGuard backend is not reachable. Start the backend service and try again.",
    };
    errorText.textContent = messages[error] || `An error occurred: ${error}`;
    errorBox.style.display = "block";
  }

  // --- Buttons ---
  document.getElementById("btn-back").addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  });

  document.getElementById("btn-continue").addEventListener("click", () => {
    if (destUrl) {
      // Validate the URL before navigating
      try {
        const parsed = new URL(destUrl);
        if (parsed.protocol === "http:" || parsed.protocol === "https:") {
          window.location.href = destUrl;
          return;
        }
      } catch (_) {}
    }
    // If URL is invalid or unsafe scheme, just close/go back
    window.close();
  });
})();
