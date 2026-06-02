# PhishGuard Browser Extension

Real-time URL phishing detection for Chrome / Edge / Brave / Arc.

## Install (unpacked)

1. Open `chrome://extensions`
2. Toggle **Developer mode** (top right)
3. Click **Load unpacked** → select the `extension/` folder
4. Pin the PhishGuard icon in your toolbar

## How it works

- Every page navigation triggers a scan in the background service worker
- Uses the same 12 heuristic indicators + Random Forest model as the web app
- Badge: `!` (dangerous), `?` (suspicious), nothing (safe)
- Desktop notification fires on dangerous URLs
- Click the icon for a full breakdown

## Files

| File | Purpose |
|------|---------|
| `manifest.json` | MV3 manifest |
| `background.js` | Service worker — scans on navigation |
| `analyzer.js` | Shared scoring logic (mirrors `src/lib/phishing-analyzer.ts`) |
| `popup.html` / `popup.js` | Toolbar popup UI |
| `icon.png` | Toolbar icon |