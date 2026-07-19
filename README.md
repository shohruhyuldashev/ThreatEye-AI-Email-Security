# ThreatEye — AI-Powered Email Security Platform

ThreatEye is a real-time phishing-detection lab where **the AI defends against AI-crafted
attacks**. It intercepts incoming mail, scores every message with a specialised local LLM
plus a deterministic detection stack, quarantines threats, and runs full-blown phishing
simulations against your own staff — all self-hosted, offline-capable, and SOC-ready.

Core pieces:

- **Specialised detection model** (`threateye-phish:1.3`, default) — a local Ollama model
  derived from qwen2.5:3b, its expertise baked in (phishing, malware, code review, ATT&CK,
  IR) with **semantic-intent reasoning**, **prompt-injection/jailbreak defence**, and two
  output modes (prose for chat, JSON for scoring). A **multilingual 7b variant** (`2.0`,
  English/Russian/Uzbek) is reproducible on demand. Any OpenAI-compatible provider also works.
- **MITRE-anchored phishing corpus** (1,210 techniques) — the model's knowledge — plus a
  **1,000,000-row labeled dataset** built from real open feeds, used to **validate**
  (benchmark) the detector at scale, not to fine-tune it.
- **Deterministic detection stack** — heuristics, SPF/DKIM/DMARC authentication, domain
  intel/typosquat, BEC signals, prompt-injection guard, and a corpus matcher — so
  detection holds when the LLM is slow or offline.
- **Real-time analysis** on two entry points: async IMAP monitoring and a machine
  ingestion API, streamed to the dashboard over SSE.
- **AI-driven GoPhish simulations** — the model writes the lure *and* the credential-capture
  landing page; GoPhish tracks who clicks and who submits (Collaborator-style).
- **Real SIEM integration** — Elasticsearch + Kibana, ECS/OCSF export, configured from the
  admin panel.
- Multi-tenant RBAC, JWT-cookie sessions, `.tap` detection plugins, adaptive learning,
  attachment malware analysis, SOC copilot, PostgreSQL evidence store.

---

## 🏗 Architecture

```
Incoming mail ──▶ IMAP watcher ─┐
Gateway/API   ──▶ /api/v1/emails ┤
                                 ▼
                       Detection pipeline
        heuristics · auth · domain-intel · corpus · BEC · injection
                     · specialised LLM (when needed)
                                 ▼
        Verdict ──▶ Quarantine ──▶ PostgreSQL evidence (IOC/MITRE/timeline)
                                 ├─▶ SIEM (ECS → Elasticsearch/Kibana)
                                 └─▶ SSE ──▶ Dashboard (:3000)
```

The `:3000` dashboard serves the UI and **proxies `/api` to the backend same-origin**, so
JWT session cookies work without CORS gymnastics.

---

## 🐳 Run locally

```bash
cp .env.example .env          # then edit the secrets
docker compose up --build     # core stack
```

- **Dashboard:** http://localhost:3000
- **Backend API:** http://localhost:8000  (health: `/health`, ready: `/ready`, metrics: `/metrics`)

Default login is `admin` / `admin` — **change it immediately** in Settings on first run.

**Optional profiles:**

```bash
docker compose --profile siem up -d elasticsearch kibana   # SIEM (Kibana on :5601)
./scripts/siem-setup.sh                                     # provision ES index + Kibana view
docker compose --profile production up                      # Caddy TLS reverse proxy
```

---

## 🤖 The AI: specialised model + knowledge base

Detection is grounded in an open-source-derived knowledge base, not guesswork.

- **Phishing corpus** (`data/phishing_corpus.json`, `scripts/build_phishing_corpus.py`) —
  1,210 concrete techniques anchored on the real **MITRE ATT&CK** Enterprise phishing tree
  (the official STIX bundle), expanded across pretext × brand × evasion × target role.
- **Labeled dataset** (`scripts/build_dataset.py`) — up to **1,000,000 rows** (phishing +
  benign) drawn from **Phishing.Database**, **OpenPhish**, **URLhaus** and the top-100k
  legitimate domains. The big file is reproducible and git-ignored; a sample + stats are
  committed.
- **Specialised model** (`scripts/build_phish_model.py`) — builds `threateye-phish:1.3`
  in Ollama: an expert system brief distilled from the corpus, classifier-tuned decoding,
  and worked examples, **baked into the model** (Ollama Modelfile) — prompt/parameter
  specialisation, **not gradient fine-tuning**. It scores emails as JSON and answers analyst
  questions as prose. A 7b multilingual variant (`--base qwen2.5:7b --name threateye-phish:2.0`)
  adds English/Russian/Uzbek chat when you want it.
- **Validated at scale** — across the 1M dataset the deterministic layer alone reaches
  **precision 99.9%, recall 86%** (false-positive rate ~0.07%). By default the LLM runs on
  every email (`DETECTOR_FAST_PATH=0`) and the deterministic checks are a safety net that can
  only raise the score; set `DETECTOR_FAST_PATH=1` to let clearly-decisive cases skip the LLM
  for speed on CPU.
- **Model persistence** — `scripts/model-archive.sh export|import` (and `MODEL.md`) archive
  the trained model as a tar (the Ollama volume, private key excluded) so it survives
  `down -v` / a host rebuild / an offline move. Large archives can be `split` for upload.
- **Governed self-improvement** (`scripts/self_improve.py`) — learns only from
  analyst-confirmed verdicts, promotes a candidate only past a validation + safety gate, and
  is bounded by an example cap, a version ceiling, a kill-switch and an audit log (human
  `--confirm` required). Never autonomous.

**Closed loop (the project's goal):** the AI generates a phishing lure + landing page, and
the AI detector catches it — verified live (generated W-2 lure, T1566.001 → quarantined).

Configure the provider from **Settings → AI Engine** (OpenAI / Anthropic / Groq /
Ollama-local / Custom, model, API key, base URL); **Test AI Connection** runs a real
completion. Talk to the model directly:

```bash
docker exec -it ollama ollama run threateye-phish:1.3
```

See [MODEL.md](MODEL.md) for where the model runs, how to rebuild, archive, and self-improve it.

---

## 🔐 Authentication & sessions

- **JWT** (PyJWT, HS256) **access + refresh tokens in httpOnly cookies** — no tokens in
  `localStorage`. Access token ~15 min, refresh ~7 days with rotation and reuse detection.
- **CSRF** double-submit: a readable `csrf_token` cookie is echoed in `X-CSRF-Token` on
  mutating requests; cookie-authed mutations are verified.
- **Same-origin** via the `:3000` nginx `/api` proxy, so the session is seamless — no
  re-login on navigation.
- Login rate-limiting (per-IP sliding window, Redis-backed), PBKDF2-HMAC-SHA256 password
  storage, generic 401s, masked secrets. See [SECURITY.md](SECURITY.md).

---

## 👥 Users, roles & ingestion API

Multi-tenant with RBAC; manage users and API keys in **Team & Access** (admin only).

**Roles:** `viewer` → `analyst` → `admin` → `owner`
- `viewer` — read-only dashboards
- `analyst` — + SOC actions (release/delete/review, empty quarantine, cases, run simulations)
- `admin` — + settings, policies, IMAP test, user & API-key management
- `owner` — + grant/revoke `owner`

**Machine ingestion** — feed mail from a gateway/connector with a per-tenant API key:

```bash
curl -X POST http://localhost:3000/api/v1/emails \
  -H "X-API-Key: tek_xxxxxxxx" -H "Content-Type: application/json" \
  -d '{
    "sender": "it@0ffice365-reset.com",
    "subject": "Mandatory password reset",
    "body": "Reset at http://0ffice365-reset.com/login and enter your password.",
    "recipient": "finance@corp.com",
    "spf": "fail", "dkim": "fail", "dmarc": "fail"
  }'
```

Returns the verdict, risk score, threat type, and recommended action; the message is
persisted with full IOC/MITRE/timeline evidence, exactly like watcher-ingested mail.
Schema changes apply at startup via an ordered SQL migration runner (`backend/migrations/`).

---

## 🛡 SOC & Blue-Team framework

The **SOC Center** view (and its APIs):

- **Triage queue** (`GET /api/triage`) — prioritised P1/P2/P3 worklist with one-click response.
- **SLA & metrics** (`GET /api/soc/metrics`) — open cases, SLA breaches, **MTTD/MTTR**
  (Critical 60m / High 4h / Medium 24h / Low 72h).
- **Threat intel** (`/api/intel/indicators`) — per-tenant blocklist/allowlist; a blocklisted
  IOC forces quarantine. Promote a confirmed email's IOCs with `block_ioc`.
- **ATT&CK coverage** (`GET /api/attack/coverage`) — defended vs observed, by tactic. Rules
  are tagged with ATT&CK techniques; the loader reads native `.yaml` and Sigma-style `.yml`.
- **Response actions** (`POST /api/emails/{id}/remediate`) — `notify`, `ticket`, `clawback`,
  `block_ioc`, recorded in `remediation_actions`.
- **Phishing corpus API** — `GET /api/corpus/stats`, `GET /api/corpus/techniques`.

---

## 🔌 SIEM integration (Elasticsearch + Kibana)

Quarantine alerts are forwarded to your SIEM in real time, **non-blocking**, with retry and
a **replay** for failed deliveries — all configured in **Settings → Integrations**.

```bash
docker compose --profile siem up -d elasticsearch kibana
./scripts/siem-setup.sh          # ECS index template + Kibana data view
```

Then set **Webhook URL** `http://elasticsearch:9200/threateye-alerts/_doc`, **Format** ECS.
Alerts are searchable in Kibana (:5601) → Discover → *ThreatEye Alerts*. Formats: `raw` /
**ECS** (Elastic) / **OCSF**. `siem_min_score` also forwards delivered-but-suspicious mail;
`POST /api/siem-events/replay` re-sends failed deliveries.

---

## 🎣 Phishing simulation (GoPhish) — fully AI-driven

Test which employees fall for phishing, by department — with the AI running the whole
campaign.

1. **Configure GoPhish** — set the URL + API key in Settings (or `GOPHISH_URL` /
   `GOPHISH_API_KEY`). The bundled `gophish` + `mail_server` work out of the box.
2. **Import the roster** (Simulations → *Employee Roster*): CSV with `email, first_name,
   last_name, department` (header aliases auto-detected; a plain email-per-line list works).
3. **Launch:**
   - **AI Automated** — the model picks a role-aware ATT&CK technique, writes the lure **and
     the brand-matched credential-capture landing page**, and launches. Flip **Automated
     scheduled campaigns** on to run every 24h.
   - **Manual** — upload a CSV (also saved to the roster) or reuse the roster.
4. **Track engagement** — GoPhish records the **click** (page load) and **data-entry** (form
   submit), Burp-Collaborator-style, then redirects. The Simulations view shows sent /
   opened / clicked / submitted, a **department-vulnerability** table, and the exact
   employees who clicked. Each campaign carries the ATT&CK technique it modelled.

API: `POST /api/simulations/targets/upload`, `POST /api/simulations/trigger`
(`mode=AI|Manual`), `GET /api/simulations/results`.

---

## 🧩 Detection plugins (`.tap`)

Extend detection without code. A **`.tap`** file is a JSON pack of *declarative* content —
detection rules, threat-intel indicators, and playbooks — with **no executable code**.
Upload from **Settings → Plugins** (`POST /api/plugins/upload`, admin); content goes live
immediately. Optional HMAC signing marks packs trusted. Spec:
[`docs/TAP_FORMAT.md`](docs/TAP_FORMAT.md); sample:
[`plugins/samples/emotet-pack.tap`](plugins/samples/emotet-pack.tap).

---

## 🧠 Adaptive learning, attachments, reports, copilot

- **Adaptive learning** — marking **Confirmed Phishing** lowers sender/URL-domain reputation
  and blocklists its IOCs; **Safe** raises reputation. Sim clickers get higher behavioural
  risk (`POST /api/simulations/sync-behavior`). `GET /api/learning/summary`.
- **Attachment malware analysis** — magic bytes, dangerous/double extensions, PDF active
  content, archives, Office macros (`oletools`), SHA-256 blocklist, optional ClamAV
  (`CLAMAV_TCP`). Malicious attachments force quarantine.
- **User-reported phishing** — `POST /api/report-phishing`; `GET /api/reports`.
- **Campaign clustering** — `GET /api/campaigns/clusters` groups related threats.
- **AI SOC copilot** — grounded Q&A (`POST /api/copilot`) and per-email AI investigation
  (`GET /api/emails/{id}/investigate`); deterministic fallback when no LLM is reachable.

---

## 🏗 Platform (tests, metrics, Redis, TLS)

- **Tests + CI:** `docker compose exec backend python -m pytest` (**40 tests**); GitHub
  Actions runs compile + tests + compose validation.
- **Observability:** Prometheus metrics at `/metrics`, `/ready`, `/health`; `LOG_LEVEL`
  controls structured logs.
- **Redis:** shared login rate-limiting across replicas (`REDIS_URL`); in-process fallback
  when unset.
- **TLS:** `docker compose --profile production up` adds a Caddy reverse proxy (`Caddyfile`)
  terminating HTTPS in front of the dashboard + API.

The `frontend-react/` directory holds a Vite + React + TS port of the UI; it is kept in the
repo but **not run** — the shipping dashboard is `frontend/` on `:3000`.

---

## ⚙ Key environment variables

| Variable | Purpose |
|----------|---------|
| `THREATEYE_AUTH_SECRET` | JWT signing key (auto-generated + persisted if unset) |
| `COOKIE_SECURE` / `COOKIE_SAMESITE` | Session-cookie flags (set `COOKIE_SECURE=true` behind TLS) |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | Database credentials |
| `AI_MODEL` / `OPENAI_API_BASE` / `OPENAI_API_KEY` | LLM provider (default `threateye-phish:1.3` on Ollama) |
| `GOPHISH_API_KEY` / `GOPHISH_URL` / `GOPHISH_VERIFY_TLS` | GoPhish integration |
| `SIEM_WEBHOOK_URL` / `SIEM_FORMAT` | SIEM export (also settable in Settings) |
| `REDIS_URL` / `CLAMAV_TCP` | Shared rate-limit state / optional attachment AV |

---

## 🧱 Tech stack

FastAPI · PostgreSQL · Redis · Ollama (`threateye-phish:1.3`, base qwen2.5:3b) ·
docker-mailserver (Postfix/Dovecot) · GoPhish · Elasticsearch + Kibana · nginx · Caddy.

---

## 📌 Project goal

A realistic, self-hosted email-security lab where AI-driven detection catches AI-crafted
phishing — with the SOC workflow, phishing simulations, and SIEM integration a blue team
actually needs. **Authorized use only:** it ships a live phishing framework and mail server;
run it on an isolated network you control.

## 🗺 Roadmap & production readiness

ThreatEye today is a **feature-complete lab/MVP**, not yet a production multi-tenant SaaS.
The honest gap list and the full team backlog to take it to enterprise/SaaS — tenant
isolation, hardening, async scale, billing/onboarding, compliance, and the AI/ML plan — live
in **[ROADMAP.md](ROADMAP.md)**. Security posture and known limitations are in
**[SECURITY.md](SECURITY.md)**.
