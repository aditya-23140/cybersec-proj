# PhishGuard — Chrome MV3 Extension

A Chrome Manifest V3 extension that intercepts link clicks and checks URLs against the PhishGuard ML backend before navigating.

## Features

- Automatically intercepts `http://` and `https://` link clicks
- Checks URLs against the PhishGuard XGBoost backend API
- Shows a warning page for suspicious or dangerous URLs
- Manual URL checker in popup
- Configurable backend URL in settings
- Sends only aggregate page-structure signals after a page loads
- Never reads cookies, credentials, form values, or page text off the device

## Installation

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `extension/` directory from this project
5. The PhishGuard icon will appear in your extensions bar

## Configuration

Click the extension icon → **⚙ Settings** to set your backend URL (default: `http://127.0.0.1:8000`).

## Backend Requirement

The extension requires the PhishGuard FastAPI backend to be running:

```bash
cd backend
uvicorn main:app --host 127.0.0.1 --port 8000
```

## Files

| File | Purpose |
|------|---------|
| `manifest.json` | Chrome extension manifest (MV3) |
| `background.js` | Service worker — handles URL check API calls |
| `content.js` | Injected into pages — intercepts link clicks |
| `popup.html/js/css` | Extension popup with manual URL checker |
| `warning.html/js/css` | Full-page warning shown for risky URLs |
| `settings.html/js` | Options page for backend URL configuration |
| `icons/` | Extension icons (16×16, 48×48, 128×128) |

## Privacy

This extension:
- ✅ Reads link `href` attributes to check clicked destinations
- ✅ Sends aggregate counts (for example password fields, external forms, iframes,
  and suspicious-word matches) to your configured backend
- ❌ Never sends page text, cookies, passwords, or form values
- ❌ Never sends data to any third-party service

## Warning Page Disclaimer

The warning page includes a clear disclaimer that:
> "This is an automated assessment based on URL and available page-structure signals. It may be incorrect. Legitimate sites can occasionally be flagged."
