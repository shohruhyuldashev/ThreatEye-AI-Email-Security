# ThreatEye dashboard (Vite + React + TypeScript)

This is the **migration target** for the dashboard. The complete, production UI still
lives in [`../frontend/`](../frontend) (vanilla HTML/JS). This app ports it to a typed,
component-based, build-tooled stack so it can grow maintainably.

## Status

Implemented as a working foundation:
- Auth flow + token handling (shares `localStorage` `threat_eye_token` with the vanilla app)
- Typed API client (`src/lib/api.ts`) and auth context (`src/lib/auth.tsx`)
- **Logical, modern routing** — a central route table (`src/routes.tsx`) is the single
  source of truth for the router (`createBrowserRouter` data router in `src/main.tsx`),
  the role-filtered sidebar, and the access rules. One nested **layout route** (`RootLayout`
  + `<Outlet/>`), declarative auth/role **guards** (`src/components/guards.tsx`), and
  **lazy code-splitting** so each route ships as its own chunk.
- Pages: Login, Dashboard, Monitor, Quarantine, SOC Center (AI Copilot), Team & Access, Plugins (.tap upload)
- Notification bell that navigates to the alert's item

Verified: `npm install` → `tsc --noEmit` clean → `vite build` produces a per-route chunk each.

Still to port from `frontend/`: Quarantine, Simulations, URL Analyzer, Analytics,
Framework, Team & Access, and the full SOC Center (triage, coverage, intel, clusters,
learning).

## Run

```bash
npm install
npm run dev        # http://localhost:5173 (proxies /api → http://localhost:8000)
npm run build      # production build to dist/
npm run typecheck  # tsc --noEmit
```

The backend must be running (see the root `docker compose up`).
