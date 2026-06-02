# PhishGuard

Real-time phishing URL detection — heuristic + Random Forest + WHOIS + community feed.

## Components

| Layer | Path | Purpose |
|-------|------|---------|
| Frontend (React + Vite) | `src/` | Scanner UI, dashboard, community feed |
| Detection engine | `src/lib/phishing-analyzer.ts` | 12 heuristic indicators + RF-style ML scoring |
| Backend edge function | `supabase/functions/whois-lookup/` | RDAP / WHOIS domain age lookup |
| Database | `supabase/migrations/` | profiles, scan_results, datasets, community_reports, report_upvotes |
| Browser extension | `extension/` | Chrome MV3 — real-time per-page scanning |
| ML training | `docs/ml-training/` | Python pipeline to retrain RF weights |

## Run locally

```bash
bun install
bun dev
```

## Package the browser extension

```bash
cd extension && nix run nixpkgs#zip -- -r ../public/phishguard-extension.zip .
```

Load `extension/` unpacked in `chrome://extensions` (Developer mode).

## Retrain the ML model

See `docs/ml-training/README.md`.