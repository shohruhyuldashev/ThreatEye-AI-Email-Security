# Changelog

## [1.17.2] - 2026-07-19
### Changed — removed the redundant :3001 React dashboard service
The `dashboard` service (React SPA on `127.0.0.1:3001`) duplicated the main dashboard on
`:3000` and is no longer run. Removed it from `docker-compose.yml` and stopped the
container. The `:3000` frontend is now the single dashboard (it already proxies `/api`
same-origin, so it stands alone). The `frontend-react/` source stays in the repo; the
production Caddy profile already proxies to `frontend`, so nothing else changes.

## [1.17.1] - 2026-07-19
### Fixed — brief login flash on navigation; session now restores seamlessly
Even with a valid session, clicking a nav item could flash the login screen for a few
milliseconds. Two causes, both fixed:
- **Login form shown before the auth check finished.** On load/navigation the login
  overlay rendered the sign-in form immediately, then `/auth/me` resolved and hid it. The
  overlay now shows a neutral **"Restoring session…" spinner** and only reveals the login
  form once the session is confirmed absent — a valid session never sees the form.
- **Parallel 401s each rotated the refresh token.** A view fires several fetches at once,
  so an expired access token produced a burst of 401s; each independently POSTed
  `/auth/refresh`, and the second rotation tripped the server's refresh-reuse detection,
  failing one call and bouncing to login. Refresh is now **single-flight** — the burst
  shares one rotation and every request retries silently, so the session stays put.

## [1.17.0] - 2026-07-18
### Fixed — session cookies dropped; every click asked for a fresh login (critical)
The real cause was cross-origin: the page on `:3000` called the API at
`http://localhost:8000` directly, so the httpOnly session cookies set by `:8000` were
not reliably sent back (and broke entirely under `127.0.0.1` vs `localhost`). The
`:3000` frontend now ships an **nginx that proxies `/api` to the backend**, and the app
calls a **relative `/api`** — so the page and the API share one origin and the session
cookies just stick. Verified end-to-end through `:3000`: login stores all three cookies,
navigation and mutations succeed, and an expired access token refreshes without a
re-login. (This is the same-origin model the `:3001` React dashboard already used.)

### Added — 1,000,000-sample dataset from real open-source feeds
`scripts/build_dataset.py` builds a **1,000,000-row labeled dataset** (600k phishing /
400k benign) from open sources: **Phishing.Database** (~410k live phishing domains),
**OpenPhish**, **URLhaus (abuse.ch)**, and the **top-100k** legitimate domains. Each real
phishing domain becomes a concrete labeled email (impersonated brand inferred, auth set
the way phishing presents); benign domains become authenticated business mail. The full
1M file is git-ignored (reproducible); a 1k sample and the stats manifest are committed.

### Fixed — detection recall on real-world phishing (validated at 1M)
Validating against the real dataset exposed that brand-lookalike detection alone recalled
only ~3% — most real phishing rides throwaway domains impersonating no famous brand.
Added an **authentication-first floor**: an unauthenticated sender (SPF/DKIM/DMARC failing)
with a link to act on is decisive on its own, since legitimate mail passes SPF. Deterministic
recall went from **2.8% → 86.2%**. Measured on **700,000 rows** of the 1M dataset (300k
phishing + 400k benign): **precision 99.90%, recall 86.21%, F1 0.926, false-positive rate
0.066%** (263 of 400k benign). The same signal is now a fast-path gate, so this bulk resolves
in ~1s without the model.

### Added — closed loop: AI catches AI-generated attacks (the project's core goal)
Verified live: the AI **generates** a phishing lure (e.g. a W-2 tax pretext, T1566.001,
with a matching credential-capture landing page) and the AI **detector catches it**
(quarantined, score 92). Real-time analysis runs on both entry points — the IMAP watcher
and the `/api/v1/emails` ingestion — through the same pipeline, streamed to the UI over SSE.

### Added — GoPhish fully AI-driven, with Burp-Collaborator-style tracking
The AI now generates the **phishing landing page** (a brand-matched credential-capture
form) per campaign, not just the email, and GoPhish records the **click** (page load) and
**data-entry** (form submit) events then redirects — the callback tracking the user asked
for. Verified end-to-end against the running GoPhish: campaign launched, AI page served,
simulated click + submit tracked (`Clicked Link → Submitted Data`), results surfaced per
department/employee in ThreatEye. Fixed the SMTP-profile from-address (GoPhish needs a bare
email) and the GoPhish-configured flag on `/simulations/config`.

### Added — expert model with skills baked into its own memory (threateye-phish:1.1)
The specialised model's system brief — held **in the model** via its Ollama Modelfile, not
loaded from external files — was expanded from phishing-only to a senior security engineer:
malware/payload analysis (macros, LOLBins, HTML smuggling, deobfuscation), secure code
review (injection, deserialization, weak crypto across Python/JS/PowerShell/Bash/SQL/PHP),
web/network security (OWASP, TLS/DNS/DMARC), MITRE ATT&CK and IR. It answers email scoring
as JSON and analyst questions as prose. Verified both modes. Re-archivable with
`scripts/model-archive.sh` (now defaults to 1.1).

### Fixed
- AI provider base URL now follows the provider preset for cloud providers (openai/anthropic/
  groq), so a stale local `ai_base_url` can't silently point cloud traffic at localhost.
- SIEM connection remains fully configurable in the admin panel (Settings → Integrations):
  webhook URL, key, auth header/prefix, format, and minimum-score, with Send Test Alert.

## [1.16.0] - 2026-07-18
### Added — MITRE-anchored phishing knowledge base + specialised model
- **1,210-technique phishing corpus** (`data/phishing_corpus.json`, built by
  `scripts/build_phishing_corpus.py`). Anchored on the real MITRE ATT&CK Enterprise
  phishing tree — the official STIX bundle from github.com/mitre/cti, 47 techniques
  (T1566/T1598/T1534/T1204/T1621/T1585/T1586/T1608 …) — then expanded across the axes
  that vary in real campaigns and that a mail product can observe: 40 pretext families ×
  41 impersonated brands × 20 evasion techniques × target role. Pairings are constrained
  to what occurs in the wild (a customs-fee lure pairs with DHL, not Okta).
- **Corpus wired into detection** (`framework/phish_corpus.py`). A pretext + impersonated
  brand + observed evasion is a named, pre-rated technique, scored **deterministically** —
  it holds when the LLM is slow, wrong or offline — and the top matches are injected into
  the analyst prompt as grounding. BEC pretexts (bank-change, wire, payroll, gift-card,
  OTP) match on the pretext alone, since a clean message *is* the attack there.
- **Specialised model `threateye-phish:1.0`** (`scripts/build_phish_model.py`): a derived
  Ollama model pinning qwen2.5:3b with an expert system prompt distilled from the corpus,
  classifier-tuned decoding (temperature 0.1, num_ctx 4096, num_predict 512) and worked
  examples that lock the JSON schema, the 0-100 scale, and the false-positive boundary.
  It is prompt/parameter specialisation over a retrieved technique library, not GPU
  fine-tuning — reproducible in seconds, inspectable, and CPU-friendly.
- **Model archiving** (`scripts/model-archive.sh export|import|list`): the trained model
  survives `docker compose down -v` / a host rebuild / a move to an offline machine. It
  archives the `ollama_data` **volume** (the weights live there, not in the image),
  excluding Ollama's private key. Produces `models/threateye-phish-1.0-<date>.tar.gz`
  (~2.7 GB, git-ignored).

### Added — detection fast path (major latency fix)
CPU inference of a 3B model runs ~45-60s per email. Now the cheap deterministic layers
run first and the **LLM is skipped when they are already decisive**: a corpus match or an
authentication+domain combination that is unambiguously hostile, or an authenticated
sender with no URLs and no signals that is unambiguously benign. Measured: clearly
malicious mail **0.07-1.0s** (was ~60s), clearly benign internal mail **0.1s**; only the
genuinely ambiguous middle (a URL that isn't a known-bad pattern) pays the model cost.
Toggle with `DETECTOR_FAST_PATH=0`.

### Added — corpus-driven simulations
Phishing simulations now draw their lure from the same corpus, so a campaign exercises a
named ATT&CK technique and is **role-aware** (Finance draws payment-fraud pretexts, IT
draws VPN/helpdesk). Each campaign carries its `attack_id`. New `GET /corpus/stats` and
`GET /corpus/techniques`; the Simulations header shows the loaded technique count.

### Fixed — session expired after 15 minutes, sending users back to login (critical)
Clicking Simulations/Quarantine (or any view) after ~15 minutes bounced the user to the
login screen. Two causes: the readable `csrf_token` cookie was issued with the **access**
token's 15-minute lifetime while the refresh token lives 7 days, so once it expired the
refresh call itself could not pass CSRF and every session died at 15 minutes; and the
vanilla frontend only kept the CSRF token in a JS variable that a page reload wiped. Fixed
by issuing the CSRF cookie with the refresh lifetime and reading it back from the cookie
on every mutating request. Verified: after the access token expires, refresh succeeds and
navigation continues without a re-login.

### Changed
- Backend image now includes `pytest`; `data/` is mounted read-only into the backend for
  the corpus. Default model is `threateye-phish:1.0`. Suite: **40/40**.

## [1.15.0] - 2026-07-18
### Fixed — detection was letting obvious phishing through (critical)
A live end-to-end test caught a credential-phishing email — Office 365 lookalike
domain, SPF **and** DKIM **and** DMARC all failing, password-harvesting body —
being scored **30/100 and delivered**. Three independent defects combined:

- **The brand list was too small.** Typosquat detection knew only 7 brands
  (`microsoft, google, apple, amazon, paypal, netflix, facebook`), so
  `0ffice365-reset.com` and `docusign-secure-sign.com` scored **0** on domain
  intel. Expanded to the brands actually impersonated in credential phishing: the
  Microsoft 365 surface (`office365`, `outlook`, `onedrive`, `sharepoint`, …),
  major SaaS/identity providers, finance, and shipping.
- **Strong signals were diluted by the weighted average.** The blend
  (`heuristics×0.22 + auth×0.10 + domain×0.20 + llm×0.20 + …`) averaged an LLM
  verdict of 82/100 together with a full authentication failure down to 30. Added
  decisive-signal floors: a confident model verdict (`llm_score ≥ 70` at
  `confidence ≥ 60`) is no longer averaged away, and SPF+DKIM+DMARC all failing
  floors the score at 60 on its own — 85 alongside a lookalike domain or heuristic
  hits. Authentication is deterministic, so this holds even when the LLM is slow,
  wrong, or unavailable.
- **Agent scores came back on the wrong scale.** The prompt specified 0-100 for
  `llm_score` but left the per-agent scores unlabelled, so smaller models answered
  0-10 — an analyst saw `score: 10` next to the verdict "High risk". The prompt now
  states the 0-100 scale with band anchors for every score field.

Verified after the fix — the missed email is now **Quarantined at 85**, an Office 365
lookalike at **90**, a DocuSign lookalike at **85**, while legitimate mail (internal
colleague, vendor newsletter with `dkim=none`, genuine Microsoft security notice)
stays **Allowed at 2-10**. No false positives introduced.

Also fixed: the domain-intel cache had stored the pre-fix zero scores and
short-circuited re-analysis, so a poisoned entry outlived the fix.

### Added — real SIEM integration (Elasticsearch + Kibana)
- `docker compose --profile siem up -d elasticsearch kibana` brings up a working SIEM
  beside the stack; ThreatEye forwards ECS alerts to
  `http://elasticsearch:9200/threateye-alerts/_doc`.
- `scripts/siem-setup.sh` provisions it idempotently: an ECS-aligned **index template**
  (so fields get real types rather than whatever dynamic mapping infers from the first
  document — a wrong inference is permanent for that index), the backing index, and a
  Kibana **data view** on `@timestamp`.
- Verified end-to-end: phishing email → detection → quarantine → SIEM dispatch →
  searchable in Kibana, with `event.action` / `labels.threat_type` aggregations working.

### Added — SIEM coverage and recovery gaps closed
- **`siem_min_score` setting.** Only *quarantined* mail used to reach the SIEM, leaving
  everything under the quarantine bar invisible — precisely the band worth hunting over.
  Delivered mail scoring at or above this value (default 40) is now forwarded as
  `threateye.email_suspicious`. Configurable in Settings → Integrations.
- **Replay for failed deliveries.** Once the 3 retries were exhausted an alert was logged
  `failed` and then lost — the alert you least want to lose. Added `POST /siem-events/replay`
  and a **Replay Failed** button; replayed rows are marked so a second call can't double-send.

### Fixed
- `test_sample_plugin_parses` failed inside the container because only `backend/` was
  mounted, so the repo-relative sample path resolved to `/plugins`. That directory is now
  mounted read-only into the backend. Suite: **40/40 passing**.

## [1.14.1] - 2026-07-06
### Changed — Real-Time Monitor rebuilt as full-width table + slide-over drawer
- The Monitor's data table was cramped into a **2/3-width** column beside a sticky detail sidebar, squeezing its 7 columns horizontally. The table is now **full width** so every column has room, and the per-email **AI analysis opens in a right-hand slide-over drawer** (Datadog/Sentry pattern) with a backdrop, close button and `Esc`-to-close. The drawer is mounted on `<body>` so `position:fixed` isn't trapped by the view's fade-in transform. All detail IDs (`monitor-detail-content`, `monitor-detail-actions`) and their populate/action logic are unchanged.
- Ships the frontend code for the 1.14.0 UX/UI overhaul (Settings sections, Simulations KPI row on top, Quarantine adaptive-height list) that the previous tag documented.

## [1.14.0] - 2026-07-06
### Changed — UX/UI overhaul of the dashboard views
- **Settings** rebuilt from a cluttered two-column grid of cards into a clean **sectioned layout** with a left-hand nav (AI Engine · Email · Integrations · Plugins · Security). Only one section shows at a time; the **Save Changes** button is pinned to the top and reachable from every section. All input IDs and handlers are unchanged, so load/save/test/plugin/password logic works as before.
- **Simulations** — the campaign KPI row (**Emails Sent · Opened · Clicked · Submitted Data**) moved to the **top** of the page and enlarged, so results read at a glance. Launch/roster, department-vulnerability and history panels follow below (nothing hidden behind tabs).
- **Real-Time Monitor** — fixed a broken layout where the table and detail panel had **no grid wrapper** (`lg:col-span-2` was inert). Table and detail sidebar now sit in a responsive `xl:grid-cols-3` layout; the cramped fixed **600px** scroll box is replaced with a **viewport-adaptive** height (`calc(100vh-15rem)`), a sticky table header, and a **sticky detail sidebar** that stays in view while the list scrolls.
- **Quarantine** — same treatment: adaptive-height list (no more 600px box), sticky table header, and a **sticky detail panel**.

## [1.13.1] - 2026-07-06
### Changed — real-time, non-blocking SIEM delivery with retry
- SIEM alerts are dispatched to a **background worker** (`ThreadPoolExecutor`) the instant an email is quarantined, so a slow or down SIEM never blocks email ingestion (`export_siem_event` now returns in <1 ms). Transient failures are **retried with backoff** (`SIEM_RETRIES`, default 3; 1s→2s→4s), and the final delivery status is recorded in `siem_events`. Verified live: instant dispatch, real-time delivery to a mock SIEM, and 3 logged retries against a dead endpoint without stalling ingestion.

## [1.13.0] - 2026-07-06
### Added — SIEM alert forwarding configurable from the SOC panel
- **SIEM destination + auth are now set in the GUI** (Settings → SIEM Alert Forwarding), not just env: webhook/HEC URL, API key/token (masked), auth header + prefix, and event format (raw / ECS / OCSF). Config resolves from settings first, then env (`SIEM_WEBHOOK_URL`, `SIEM_API_KEY`, `SIEM_AUTH_HEADER`, `SIEM_AUTH_PREFIX`, `SIEM_FORMAT`).
- **Flexible SIEM auth** covers the common backends — Splunk HEC (`Authorization: Splunk <token>`), Elastic (`ApiKey`), Datadog (`DD-API-KEY`), or generic `Bearer` — via the header + prefix fields.
- **"Send Test Alert" button** (`POST /api/settings/test-siem`, admin) posts a synthetic event and reports the HTTP result, so you can validate connectivity before relying on it.
- Quarantine alerts auto-forward with the configured auth + format; every attempt's delivery status (sent / failed / skipped, HTTP code, error) is recorded and shown in Framework → SIEM events.
- Verified live end-to-end against a mock SIEM: GUI config → test alert delivered (HTTP 200) with the `Authorization: Splunk <token>` header in ECS format, a real quarantine forwarded `threateye.email_alert`, and `/api/siem-events` showed `sent`.

## [1.12.0] - 2026-07-05
### Changed — modern cookie-based JWT sessions (replaces Bearer + localStorage)
- **Standard JWT (HS256)** access + refresh tokens (PyJWT) with `sub/uid/org/role/type/iat/exp/jti` claims, replacing the custom HMAC token. Short-lived **access** (15 min) + long-lived **refresh** (7 days), both delivered as **httpOnly cookies** — no token in JS/localStorage (XSS-safe). Tunable via `ACCESS_TOKEN_TTL_SECONDS` / `REFRESH_TOKEN_TTL_SECONDS`.
- **Refresh rotation + reuse detection.** `POST /api/auth/refresh` validates the refresh cookie, one-time-uses its `jti` (tracked in Redis), and issues fresh cookies; a replayed old refresh token is rejected (401). `POST /api/auth/logout` revokes the refresh token and clears cookies. Stateless fallback if Redis is absent.
- **CSRF protection** (double-submit): a readable `csrf_token` cookie must be echoed in the `X-CSRF-Token` header on mutating requests that authenticate via cookie; `CSRFMiddleware` enforces it. Header/API-key clients are exempt (not CSRF-vulnerable).
- **`require_auth`** now resolves the session from the `access_token` cookie first, then `Authorization: Bearer` (API/CLI), then `?token=` (SSE). CORS switched to `allow_credentials=true` with explicit origins.
- **Both frontends migrated to cookies:** the React SPA reads the CSRF cookie (same-origin) and transparently refreshes on 401; the vanilla app keeps the CSRF token from the login/refresh body (cross-origin) — neither stores a token. SSE now authenticates via the cookie (`withCredentials`), dropping the `?token=` query param.
- Verified live end-to-end: login sets httpOnly cookies (real JWT), CSRF blocks (403) / passes (200), refresh rotates, refresh reuse → 401, logout revokes, Bearer fallback works, and the flow works through the same-origin dashboard proxy. Set `COOKIE_SECURE=true` (and serve over TLS) in production.

## [1.11.1] - 2026-07-05
### Fixed
- **Ollama crash-loop.** The compose `ollama` entrypoint pulled `glm-4.5` (not a real model) with `&& wait`, so a failed/slow pull exited the container and it restarted every ~30s — which aborted any manual `ollama pull`. Entrypoint is now resilient (`... || echo …; wait`, serves first, best-effort pull), the default model is a real one (`qwen2.5:3b`), and `mem_limit: 6g` protects the host (no swap).
- **Detector required outbound internet.** `tldextract`/`urlextract` fetched the public-suffix/TLD list at runtime and crashed analysis in a locked-down container. New `framework/netutil.py` uses the bundled snapshots only (regex fallback for URLs); `ai_detector` and `learning` now use it. Verified: a URL-bearing email is analysed end-to-end with zero egress.
- **LLM timeout too short for local CPU models.** `LLM_TIMEOUT` default raised 20s → 90s (env-tunable) — a 3B model's first (cold-load) JSON-mode call exceeded 20s and silently fell back to heuristics. Verified end-to-end with **qwen2.5:3b** on Ollama: `test-ai` OK, SOC Copilot answers from tenant data, and the email detector produces a real multi-agent LLM verdict + explanation.

### Notes — running Ollama with no container internet
If Docker containers can't reach the internet but the host can, pull the model once via a
host-networked helper into the shared volume, then serve it normally (serving needs no
internet):
```
docker run -d --name ollama_pull --network host -e OLLAMA_HOST=127.0.0.1:11500 \
  -v <project>_ollama_data:/root/.ollama ollama/ollama
docker exec -e OLLAMA_HOST=127.0.0.1:11500 ollama_pull ollama pull qwen2.5:3b
docker rm -f ollama_pull && docker compose up -d ollama
```

## [1.11.0] - 2026-07-05
### Added — Production React dashboard + full endpoint audit
- **React SPA is now a production frontend.** Multi-stage `frontend-react/Dockerfile` (build → nginx) + `nginx.conf` with **SPA fallback** (deep links / refresh work with client-side routing) and a same-origin **`/api` reverse proxy** to the backend (no CORS, SSE-friendly). New compose service **`dashboard`** on port 3001. The app ships as minified, hashed, per-route chunks — no readable monolithic `app.js`.
- **Modern logical routing** (`frontend-react`): `createBrowserRouter` data router driven by a central route table (`src/routes.tsx`) that is the single source of truth for the router, the role-filtered sidebar, and access rules; one nested layout route (`<Outlet/>`), declarative `RequireAuth`/`RequireRole` guards, lazy per-route code-splitting. Verified with `tsc --noEmit` + `vite build`.

### Fixed
- **`GET /api/analytics` 500** — queried non-existent `ai_reason`/`recipient` columns on `emails`; now uses `ai_analysis_log`/`threat_type` and joins `quarantine` for recipients, tenant-scoped.
- **`GET /api/simulations/config` 500** — the literal `%` in `LIKE 'sim_%'` collided with psycopg2 parameter formatting. Fixed globally in the DB shim: no-param queries no longer pass an (empty) params sequence, so literal `%` is left intact.
- **`POST /api/settings/test-imap`** now accepts an empty body (fields optional) and falls back to saved credentials instead of 422.

### Verified
- Live end-to-end audit of **all 70 endpoints**: 52 pass, 3 correct error responses from intentionally-absent externals (Ollama/mail/GoPhish), auth (401) and role (403) enforcement confirmed, API-key ingestion + revocation confirmed. 0 unexpected failures.

## [1.10.0] - 2026-07-05
### Added — Plugin system (.tap), multi-provider AI, notification fix
- **Detection plugins — the `.tap` format** (`framework/plugins.py`, `plugins` table, `docs/TAP_FORMAT.md`). A `.tap` is a JSON pack of **declarative** detection content (rules + threat-intel + playbooks) with **no executable code** — the key supply-chain safety property. Upload from Settings → Plugins (`POST /api/plugins/upload`, admin); content becomes live immediately (rules join the engine, intel joins the blocklist, playbooks register). Optional HMAC signing (`plugin_signing_key`) marks plugins trusted vs unverified. Endpoints: `GET /api/plugins`, `POST /api/plugins/{id}/toggle`, `DELETE /api/plugins/{id}`. Sample: `plugins/samples/emotet-pack.tap`. 8 new unit tests.
- **GUI-configurable, multi-provider AI** (`framework/model_provider.py`). The active model is set from Settings → AI Engine (provider, model, API key, base URL) and resolved live per request — no redeploy. Works with any OpenAI-compatible provider: **OpenAI, Anthropic, Groq, Ollama (local), or a custom endpoint**. New **Test AI Connection** button (`POST /api/settings/test-ai`) does a live completion. `ai_api_key` is masked.
- **IMAP Test Connection fixed.** Blank/masked fields now fall back to the saved credentials (the previous bug sent the masked `********` as the password, so the test always failed), with a short timeout and clearer errors.
- **Notifications are clickable.** The bell items now navigate to the exact quarantined email (the inline handler referenced a non-global `switchView` and silently threw); `/notifications` now returns the `email_id`.
- **React SaaS frontend expanded** (`frontend-react/`): typed API client, notification bell, and Dashboard / Monitor / Quarantine / SOC-Copilot / Team / **Plugins** pages with role-gated nav.

## [1.9.0] - 2026-07-05
### Added — Platform hardening, real mailbox clawback, React frontend scaffold
- **Test suite + CI.** `backend/tests/` pytest suite (32 tests: auth/RBAC/tokens, SIEM formatters, SLA, ATT&CK, attachment scanner, clustering, roster parsing, reputation, metrics, clawback) and a GitHub Actions workflow (`.github/workflows/ci.yml`) running compile + pytest + compose-config + advisory Semgrep.
- **Observability.** Dependency-free Prometheus exporter at `/metrics` (request counters + latency histogram via `MetricsMiddleware`), a `/ready` DB-readiness probe, and structured logging (`LOG_LEVEL`).
- **Redis-backed shared rate-limiting.** The login limiter now uses Redis when `REDIS_URL` is set (correct across replicas) and falls back to the in-process window otherwise. New `redis` service in compose; `framework/cache.py` is offline-safe.
- **TLS reverse proxy.** Optional Caddy service + `Caddyfile` under the `production` compose profile (`docker compose --profile production up`) terminating HTTPS and proxying dashboard + API.
- **Real mailbox clawback** (`framework/mail_remediation.py`). The `clawback` response action now performs a real **Microsoft 365 Graph** (app-only) or **Google Workspace** (service-account, domain-wide delegation) soft-delete across configured mailboxes, falling back to the webhook/record path. Provider creds are Settings-configured and masked (`google_sa_json` now treated as sensitive).
- **React migration scaffold** (`frontend-react/`, Vite + React + TypeScript): typed API client, auth context + protected routing, sidebar layout, and Login/Dashboard/Monitor/SOC-Copilot pages — a maintainable target to port the vanilla `frontend/` into. The existing dashboard is unchanged.

## [1.8.0] - 2026-07-05
### Added — Adaptive learning (feedback loop)
- **Verdict-driven reputation** (`framework/learning.py`, `reputation` table). Analyst decisions now change future scoring: **Confirmed Phishing** lowers the sender/URL-domain reputation and auto-blocklists the IOCs; **Marked Safe** raises the sender reputation so the same benign sender stops being re-flagged (fewer repeat false positives). Applied at ingest via `apply_reputation` — a learned-bad sender adds to the risk score (and can force quarantine), a learned-trusted one reduces it, both surfaced in the evidence.
- **Simulation → behavioural risk.** `POST /api/simulations/sync-behavior` folds GoPhish click/submit outcomes into `user_profiles` (repeat clickers get a higher `behavioral_risk_score` and `failed_simulations_count`), which the detector already factors into scoring for those employees' inbound mail — closing the sim→detection loop.
- **Learning dashboard.** `GET /api/learning/summary` and `GET /api/learning/reputation` expose false-positive count, confirmed phishing, learned-bad/trusted counts, repeat clickers, and top learned reputation. New "Adaptive Learning" card in the SOC Center with a one-click behaviour sync.

## [1.7.0] - 2026-07-05
### Added — Attachment malware analysis, reported-phishing intake, campaign clustering, AI copilot
- **Attachment malware analysis** (`framework/attachment_scanner.py`). Every attachment is now scanned, not just recorded: magic-byte type detection, dangerous/double extensions, extension↔content mismatch (disguised executables), PDF active content (`/JavaScript`, `/OpenAction`, `/Launch`), archive inspection (executables inside / encrypted zips), Office macros via `oletools` (if installed), SHA-256 reputation against the tenant blocklist, and an optional ClamAV `clamd` INSTREAM scan (`CLAMAV_TCP`). A malicious attachment (≥80) forces quarantine; verdict/score/sha256/signals are stored per attachment. The IMAP watcher now passes attachment payloads through the shared ingest pipeline.
- **User-reported phishing intake.** `POST /api/report-phishing` analyses a forwarded suspicious email, stores it (`source=user_report`), and opens a report; `GET /api/reports` lists them.
- **Campaign clustering** (`framework/clustering.py`, `GET /api/campaigns/clusters`). Recent inbound threats are grouped into likely campaigns by sender domain + normalised subject, so analysts triage a campaign instead of N near-identical alerts.
- **AI SOC copilot** (`framework/copilot.py`). `POST /api/copilot` answers natural-language questions grounded in the tenant's own detections (read-only), and `GET /api/emails/{id}/investigate` returns an AI-written investigation narrative (verdict / why / impact / next steps). Both are offline-safe with a deterministic fallback.
- **Frontend:** SOC Center gains an AI Copilot chat and a Campaign Clusters panel; the email detail gains an "AI Investigate" button. Emails now carry a `source` tag (watcher / api / user_report).

## [1.6.0] - 2026-07-05
### Added — Full AI-automated phishing simulation (GoPhish)
- **Employee roster from CSV.** Upload `email, first_name, last_name, department` (headers auto-detected via aliases; a plain email-per-line list also works). Stored per-tenant in `sim_targets`. Endpoints: `POST /api/simulations/targets/upload`, `GET /api/simulations/targets`, `DELETE /api/simulations/targets`.
- **Real GoPhish campaigns.** `launch_campaign` now provisions the full stack — SMTP sending profile + credential-capture landing page + group + template + campaign — so emails are actually sent and clicks/opens/submissions are tracked. (Previously only a group+template were created and nothing was sent.)
- **AI-automated mode.** The LLM crafts the lure and targets come from the roster (optionally a department and a random sample); launched via the GoPhish API. `sim_auto_enabled` gates a 24h scheduled automated campaign.
- **Manual mode.** Upload a CSV (also saved to the roster) or reuse the stored roster/department, then launch.
- **Per-department / per-employee tracking.** `GET /api/simulations/results` returns per-campaign totals, per-department open/click/submit rates, and the list of employees who clicked or submitted (department carried in the GoPhish `position` field). Launched campaigns are registered in `sim_campaigns`.
- **Frontend Simulation view rebuilt:** roster import with per-department summary, AI/Manual launch controls (department filter, sample size, lure theme), an automation toggle, result tiles, a department-vulnerability table, a caught-employees list, and campaign history.

### Fixed
- PDF victim detection used the wrong GoPhish status string (`Clicked` → `Clicked Link`).

## [1.5.0] - 2026-07-05
### Added — SOC & Blue-Team framework
- **Threat-intel enrichment.** Per-tenant blocklist/allowlist (`intel_indicators`); extracted IOCs are checked at ingest — a blocklist match forces quarantine and is surfaced in the evidence. Endpoints: `GET/POST /api/intel/indicators`, `DELETE /api/intel/indicators/{id}`. Confirmed-phishing IOCs can be promoted to the blocklist (`block_ioc` action).
- **SOC metrics & SLA.** Cases now carry `sla_minutes`/`due_at`/`first_response_at`/`resolved_at`; case updates stamp first-response and resolution. `GET /api/soc/metrics` returns open cases, SLA breaches, and **MTTD/MTTR**.
- **Triage queue.** `GET /api/triage` — a prioritised (P1/P2/P3) analyst worklist of emails needing attention.
- **Detection-as-Code + ATT&CK coverage.** Rule loader now reads native `.yaml` and **Sigma-style `.yml`** files and tags rules with ATT&CK technique/tactic. `GET /api/attack/coverage` returns a defended-vs-observed coverage matrix by tactic.
- **Remediation / response.** `POST /api/emails/{id}/remediate` runs `notify` (Slack/Teams), `ticket` (Jira), `clawback`, and `block_ioc` actions — all offline-safe and recorded in `remediation_actions` (`GET /api/remediation`).
- **SIEM schema normalisation.** SIEM export can emit **ECS** or **OCSF** (Email Activity) in addition to raw, via the `siem_format` setting (or `SIEM_FORMAT`).
- **Frontend "SOC Center" view:** metric tiles, triage queue with one-click response actions, ATT&CK coverage grid, and threat-intel management.

## [1.4.0] - 2026-07-05
### Added — SaaS foundation (multi-tenancy, users & RBAC, ingestion API)
- **Multi-user auth with RBAC.** New `users` table replaces the single hard-coded admin. Four roles: `viewer` < `analyst` < `admin` < `owner`. Login, `/auth/me`, and self-service password change now run against user records. The default `admin` user is seeded (and its password migrated from the legacy `admin_password` setting) so the existing login keeps working.
- **Role-gated endpoints.** Writes are enforced by role: settings/policies/IMAP-test/user-&-key management require `admin`; SOC actions (release, delete, review, empty-quarantine, case update, trigger simulation) require `analyst`; reads require any authenticated role.
- **User management API:** `GET/POST /api/users`, `POST /api/users/{id}`, `DELETE /api/users/{id}` (last-owner and self-lockout protections).
- **Tenant API keys + machine ingestion:** `GET/POST /api/keys`, `DELETE /api/keys/{id}` (key shown once), and `POST /api/v1/emails` authenticated by `X-API-Key`, scoped to the key's tenant, running the full detection pipeline.
- **Multi-tenancy:** `organization_id` on `emails`/`simulations`; core read paths (stats, emails, quarantine, live SSE stream) and all new writes are tenant-scoped.
- **Migration runner:** dependency-free ordered SQL migrations in `backend/migrations/` tracked in `schema_migrations` (applied on startup), replacing ad-hoc schema drift.
- **Shared ingestion pipeline** (`services/ingest.py`): the IMAP watcher and the API ingestion endpoint now share one tenant-aware persist path, so they can't drift.
- **Frontend "Team & Access" view:** manage users, roles, and API keys; admin-only nav is hidden by role via `/auth/me`.

## [1.3.0] - 2026-07-05
### Security
- Added per-IP rate limiting and audit logging (`login_success` / `login_failed`) to the login endpoint to stop brute-force / credential stuffing.
- Login now returns a single generic error for bad username or password (no user enumeration).
- Token signing secret is resolved from `THREATEYE_AUTH_SECRET` or auto-generated and persisted, replacing the shipped `change-me-in-production` default.
- `admin_password` and `auth_secret` are excluded from the settings API.
- Added `SecurityHeadersMiddleware` (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control`).
- Tightened CORS: explicit methods/headers, credentials disabled (API is bearer-token based).
- Compose now binds Postgres and Ollama to `127.0.0.1` only.
- Added `.env.example`, `.dockerignore`, and `SECURITY.md`.

### Added
- Real SPF / DKIM / DMARC verdicts and reply-to-mismatch parsing from message headers (replaces the hard-coded `dkim=pass`); DMARC failure now feeds the risk score.
- `/health` liveness endpoint.
- Database indexes on the dashboard / monitor / quarantine hot paths.

### Fixed
- PDF report filename used minutes (`%M`) instead of month (`%m`).
- Reduced base64-obfuscation heuristic false positives (contiguous-blob match with a higher length floor).
- Dashboard no longer flashes fabricated placeholder counts before real stats load.
- Expanded suspicious-TLD and URL-shortener lists.

## [1.1.0] - 2026-02-25
### Improved
- Enhanced typosquatting scoring
- Improved risk keyword calibration
- Updated classification thresholds

## [1.0.0] - 2026-02-25
### Added
- Initial SaaS-ready architecture
- Async IMAP IDLE monitoring
- LLM-based phishing detection
- Automatic quarantine
- GoPhish integration
