# ThreatEye – AI Powered Email Security Platform

ThreatEye is a real-time phishing detection platform that combines:

- Docker Mailserver (Postfix + Dovecot)
- Async IMAP IDLE Monitoring
- LLM-based Analysis (Ollama / Phi-3)
- Rule-based + Hybrid Threat Detection
- Automatic IMAP Quarantine
- GoPhish Simulation Integration
- PostgreSQL-backed SOC evidence, feedback, timeline, and domain-intel cache
- Plugin-style detection engine framework
- Policy engine, audit log, and case management foundation
- Attachment metadata scanning layer
- Model provider abstraction for Ollama/OpenAI-compatible APIs
- IOC extraction for URLs, domains, IPs, emails, hashes, and filenames
- MITRE ATT&CK mapping for SOC-ready context
- SIEM webhook export (`SIEM_WEBHOOK_URL`)
- SOAR-style playbook execution
- Detection-as-Code YAML rules in `backend/rules/`

---

## 🏗 Architecture

Internet → Postfix (SMTP)
→ Dovecot (IMAP)
→ Async Email Watcher (IDLE)
→ AI Detection Engine
→ Auto Quarantine (IMAP Folder Move)
→ PostgreSQL Evidence Store
→ Dashboard (Frontend + API)

---

## 🔥 Features

- Real-time email interception
- Async IMAP IDLE monitoring
- Typosquatting detection
- URL threat scoring
- LLM reasoning engine
- AI Mode 2.0 multi-agent SOC verdicts
- Prompt-injection guard for adversarial email content
- BEC / payment fraud signal detection
- Evidence-based recommendations and analyst review workflow
- Domain intelligence cache
- Policy-driven quarantine / hold-for-review decisions
- Framework Center for policies, cases, audit trail, and module status
- IOC, MITRE, SIEM, playbook, and detection-rule APIs
- Automatic quarantine folder move
- Docker-based production-style setup

---

## 🐳 Run Locally

```bash
cp .env.example .env      # then edit the secrets
docker compose up --build
```

Dashboard (production React SPA): [http://localhost:3001](http://localhost:3001) — modern per-route
code-split routing, served by nginx with a same-origin `/api` proxy.
Legacy single-file dashboard: [http://localhost:3000](http://localhost:3000)
Backend API: [http://localhost:8000](http://localhost:8000)
Health check: [http://localhost:8000/health](http://localhost:8000/health)

Default login is `admin` / `admin` — **change it immediately** from Settings on first run.

---

## 🔐 Security & Configuration

ThreatEye ships a live phishing framework (GoPhish) and a mail server, so run it only on
an isolated network you are authorised to test. Before real use:

1. Copy `.env.example` → `.env` and set `THREATEYE_AUTH_SECRET` and `POSTGRES_PASSWORD`.
2. Change the default `admin` password.
3. Lock `CORS_ALLOWED_ORIGINS` to your dashboard origin and terminate TLS at a reverse proxy.

Built-in hardening (login rate limiting, PBKDF2 password hashing, signed session tokens,
security headers, SPF/DKIM/DMARC scoring, localhost-bound internal services) and the full
list of known limitations are documented in [SECURITY.md](SECURITY.md).

Key environment variables:

| Variable | Purpose |
|----------|---------|
| `THREATEYE_AUTH_SECRET` | Session-token signing key (auto-generated + persisted if unset) |
| `THREATEYE_LOGIN_MAX_ATTEMPTS` / `THREATEYE_LOGIN_WINDOW_SECONDS` | Login rate-limit tuning |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | Database credentials |
| `AI_MODEL` / `OPENAI_API_BASE` / `OPENAI_API_KEY` | LLM provider (Ollama or OpenAI-compatible) |
| `GOPHISH_API_KEY` / `GOPHISH_VERIFY_TLS` | GoPhish integration |
| `SIEM_WEBHOOK_URL` | Optional SOC/SIEM export endpoint |
| `CORS_ALLOWED_ORIGINS` | Comma-separated allowed dashboard origins |

---

## 👥 Users, Roles & Ingestion API (SaaS foundation)

ThreatEye is multi-tenant with role-based access control. Manage users and API keys
from the **Team & Access** view (admin only).

**Roles** (increasing privilege): `viewer` → `analyst` → `admin` → `owner`
- `viewer` — read-only dashboards
- `analyst` — + SOC actions (release/delete/review, empty quarantine, case updates, run simulations)
- `admin` — + settings, policies, IMAP test, user & API-key management
- `owner` — + can grant/revoke the `owner` role

**Machine ingestion API** — feed emails from a gateway/connector, authenticated by an
API key (create one in Team & Access, scoped to your tenant):

```bash
curl -X POST http://localhost:8000/api/v1/emails \
  -H "X-API-Key: tek_xxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "hr@miicrosoft.com",
    "subject": "Mandatory password reset",
    "body": "Click http://miicrosoft.com/login to keep your account.",
    "recipient": "finance@corp.com",
    "spf": "fail", "dkim": "fail", "dmarc": "fail"
  }'
```

Returns the verdict, risk score, threat type, and recommended action; the message is
persisted with full IOC/MITRE/timeline evidence exactly like watcher-ingested mail.

Schema changes are applied at startup by an ordered SQL migration runner
(`backend/migrations/`), tracked in the `schema_migrations` table.

---

## 🛡 SOC & Blue-Team framework

The **SOC Center** view (and its APIs) give analysts an operational workspace:

- **Triage queue** (`GET /api/triage`) — prioritised P1/P2/P3 worklist of emails needing action, with one-click response.
- **SLA & metrics** (`GET /api/soc/metrics`) — open cases, SLA breaches, **MTTD/MTTR**. Cases get an SLA target by severity (Critical 60m / High 4h / Medium 24h / Low 72h).
- **Threat intel** (`/api/intel/indicators`) — per-tenant blocklist/allowlist; a blocklisted IOC in an inbound email forces quarantine. Promote a confirmed phishing email's IOCs with the `block_ioc` action.
- **ATT&CK coverage** (`GET /api/attack/coverage`) — defended (by enabled rules) vs. observed (in traffic), by tactic. Detection rules are tagged with ATT&CK techniques; the loader reads native `.yaml` **and Sigma-style `.yml`** rules from `backend/rules/`.
- **Response actions** (`POST /api/emails/{id}/remediate`) — `notify` (Slack/Teams), `ticket` (Jira), `clawback`, `block_ioc`. Every action is recorded in `remediation_actions`.
- **SIEM normalisation** — export alerts as **ECS** or **OCSF** (or raw) so your SIEM ingests them without a custom parser.

---

## 🎣 Phishing simulation (GoPhish) — AI-automated & manual

Test which employees fall for phishing, broken down by department.

1. **Configure GoPhish** — set the GoPhish URL + API key in Settings (or `GOPHISH_URL` / `GOPHISH_API_KEY`). The bundled `gophish` service and `mail_server` work out of the box in the lab.
2. **Import the roster** (Simulation view → *Employee Roster*) — a CSV with headers:

   ```csv
   email,first_name,last_name,department
   john.doe@corp.com,John,Doe,Finance
   jane.roe@corp.com,Jane,Roe,Sales
   ```

   Header aliases (`mail`, `name`, `dept`, `team`, `position`…) are auto-detected, and a plain one-email-per-line file also works.
3. **Launch a campaign:**
   - **AI Automated** — the LLM writes the lure; targets come from the roster (optionally one department / a random sample). Flip **Automated scheduled campaigns** on (`sim_auto_enabled`) to have it run every 24h.
   - **Manual** — upload a CSV (also saved to the roster) or reuse the roster, then launch.
4. **Track engagement** — the Simulation view shows emails sent / opened / clicked / submitted, a **department-vulnerability** table, and the exact **employees who clicked**. GoPhish provisions the sending profile, landing page, and campaign automatically.

API: `POST /api/simulations/targets/upload`, `GET /api/simulations/targets`, `POST /api/simulations/trigger` (`mode=AI|Manual`), `GET /api/simulations/results`.

Simulation settings (defaults target the lab services): `SIM_SMTP_HOST`, `SIM_SMTP_FROM`, `SIM_PHISH_URL`.

---

## 🧩 Detection plugins (`.tap`)

Extend detection without code. A **`.tap`** file is a JSON pack of *declarative* content —
detection rules, threat-intel indicators, and playbooks — with **no executable code**, so
third-party packs are safe to install. Upload from **Settings → Plugins** (`POST /api/plugins/upload`,
admin); content goes live immediately. Optional HMAC signing marks packs trusted. Format spec:
[`docs/TAP_FORMAT.md`](docs/TAP_FORMAT.md); sample: [`plugins/samples/emotet-pack.tap`](plugins/samples/emotet-pack.tap).

## 🤖 AI provider (GUI-configurable)

Set the model from **Settings → AI Engine**: provider (OpenAI / Anthropic / Groq / Ollama-local /
Custom), model, API key, and base URL — resolved live per request. The **Test AI Connection** button
runs a real completion (`POST /api/settings/test-ai`). Any OpenAI-compatible endpoint works.

---

## 🧠 Adaptive learning (feedback loop)

Analyst decisions and simulation outcomes tune future detection:

- Marking an email **Confirmed Phishing** lowers the sender/URL-domain reputation and blocklists its IOCs; marking it **Safe** raises the sender's reputation so it stops being re-flagged. Learned reputation adjusts the risk score at ingest (`framework/learning.py`).
- **Sync sim behaviour** (`POST /api/simulations/sync-behavior`) raises the behavioural risk of employees who clicked in a simulation — the detector then scrutinises their inbound mail more closely.
- See it in the SOC Center **Adaptive Learning** card, or `GET /api/learning/summary` · `GET /api/learning/reputation`.

---

## 🧪 Attachment analysis, reported phishing, clustering & AI copilot

- **Attachment malware analysis** — every attachment is scanned: file-type (magic bytes), dangerous/double extensions, disguised executables, PDF active content, archive contents, Office macros (`oletools`), SHA-256 blocklist reputation, and optional ClamAV (`CLAMAV_TCP=host:port`). Malicious attachments force quarantine.
- **User-reported phishing** — `POST /api/report-phishing` (forwarded email → auto-triaged report); `GET /api/reports`.
- **Campaign clustering** — `GET /api/campaigns/clusters` groups related inbound threats so you triage a campaign, not 200 alerts.
- **AI SOC copilot** — ask questions grounded in your data (SOC Center chat / `POST /api/copilot`), and get an AI-written **investigation** per email (`GET /api/emails/{id}/investigate`, or the "AI Investigate" button). Both fall back to a deterministic summary when no LLM is reachable.

---

## 🏗 Platform (tests, metrics, Redis, TLS)

- **Tests + CI:** `cd backend && pytest` (32 unit tests); GitHub Actions runs compile + tests + compose validation on every push.
- **Observability:** Prometheus metrics at `/metrics`, readiness at `/ready`, liveness at `/health`; `LOG_LEVEL` controls structured logs.
- **Redis:** shared login rate-limiting across replicas (`REDIS_URL`); safe in-process fallback when unset.
- **TLS:** `docker compose --profile production up` adds a Caddy reverse proxy (`Caddyfile`) terminating HTTPS in front of the dashboard + API.

The dashboard is also being ported to **Vite + React + TypeScript** in [`frontend-react/`](frontend-react) (typed API client, auth, routing, and core pages) — a maintainable migration target; the shipping UI remains `frontend/`.

---

## 🔌 Response / SIEM integrations

Response/SIEM integrations are configured as settings (all optional; unconfigured = safely skipped). Real mailbox **clawback** uses Microsoft 365 Graph or Google Workspace when configured:

| Setting | Purpose |
|---------|---------|
| `siem_format` | `raw` \| `ecs` \| `ocsf` export schema |
| `slack_webhook_url` / `teams_webhook_url` | Chat notifications for `notify` |
| `jira_url` / `jira_token` / `jira_project` | Ticket creation for `ticket` |
| `m365_tenant_id` / `m365_client_id` / `m365_client_secret` / `m365_mailboxes` | Real M365 Graph clawback (app needs `Mail.ReadWrite`) |
| `google_sa_json` / `google_mailboxes` | Real Google Workspace clawback (service account, domain-wide delegation) |
| `remediation_webhook_url` | Fallback target for `clawback` dispatch |

---

## ⚙ Tech Stack

* FastAPI
* Docker
* Dovecot
* Postfix
* Ollama (default model: GLM 4.5 via `glm-4.5`, configurable with `AI_MODEL` / `OLLAMA_MODEL`)
* PostgreSQL
* GoPhish

---

## 📌 Project Goal

Build a realistic enterprise-style email security lab environment with AI-driven phishing detection and automated quarantine workflows.
