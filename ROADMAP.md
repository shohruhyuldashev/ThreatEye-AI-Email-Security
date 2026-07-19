# ThreatEye — Roadmap: from lab to enterprise SaaS

This document is the **team backlog** for taking ThreatEye from its current state (a
feature-complete, self-hosted lab/MVP) to something companies can deploy and that can be
sold globally as a product/SaaS. It is honest about what is missing and orders the work by
what blocks real use first.

> **Progress (2026-07-19):** ✅ tenant isolation complete (all reads org-scoped, cross-tenant tested) · ✅ settings secrets encrypted at rest (Fernet) · ✅ production hardening (no `--reload`, workers, startup secret guard) · ✅ per-tenant ingestion rate limits. Next: async task queue, signup/billing.
>
> **Current verdict.** ThreatEye works end-to-end and is a strong foundation, but it is
> **not yet a production multi-tenant SaaS**. It is safe today only as an **internal tool or
> a single-organization, authorized pilot** on an isolated network, after basic hardening.
> The single biggest blocker to selling it as a SaaS is **incomplete tenant isolation**.

---

## 1. Where it is today

**Already built and verified**
- Detection pipeline: deterministic stack (auth / domain-intel / corpus / BEC / injection)
  **validated on a 1M dataset at 99.9% precision, 86% recall**, plus a specialised local LLM
  (`threateye-phish:1.3`, semantic-intent + injection defence, two output modes).
- SOC/Blue-team: cases + SLA/MTTD/MTTR, triage, ATT&CK coverage, threat-intel, Sigma rules,
  SIEM export (ECS/OCSF → Elasticsearch/Kibana, verified end-to-end), SOAR-style playbooks.
- Phishing simulation (GoPhish): AI-generated lure + landing page, click/submit tracking.
- Platform: multi-tenant data model, RBAC (viewer→owner), API-key ingestion, SQL migrations,
  JWT-cookie sessions + CSRF, Redis rate-limited login, `.tap` plugins, adaptive learning,
  attachment malware analysis, Prometheus metrics, 40 tests + CI.

**What it is NOT (yet)**
- Not a hardened production service (dev conveniences still on).
- Not safely multi-tenant (see §2.1 — cross-tenant reads possible).
- Not scalable for real mail volume (LLM runs inline, ~1–3 min/email on CPU).
- Not a commercial product (no signup, billing, onboarding, plans).

---

## 2. Known limitations (current, verified against the code)

### 2.1 Security & tenant isolation — **CRITICAL, do first**
- **Incomplete tenant scoping.** Several read endpoints do **not** filter by
  `organization_id` — `GET /iocs`, `/cases`, `/audit-log`, `/siem-events`,
  `/mitre-mappings`. In a multi-tenant deployment one customer can read another customer's
  data. **This is a hard blocker for any SaaS.**
- **Admin-authenticated SSRF surface.** `test-imap`, `test-siem`, the URL analyzer and WHOIS
  reach arbitrary hosts by design; in a hosted setting a tenant admin could probe internal
  infrastructure. Needs egress allow-listing / a broker.
- **Secrets stored in plaintext in the DB.** SIEM/AI/GoPhish/M365/Google credentials are
  masked in the API but not encrypted at rest. Needs envelope encryption (KMS/Vault/Fernet).
- **Dev conveniences shipped on.** `--reload` in the backend Dockerfile (single worker),
  `COOKIE_SECURE=false`, `admin/admin` default, no TLS by default (Caddy is an optional profile).
- **No per-tenant rate limit / quota** on the ingestion API (`POST /v1/emails`) — only login
  is rate-limited.

### 2.2 Scale & performance
- **LLM runs inline on every request** (`DETECTOR_FAST_PATH=0`), ~1–3 min/email on CPU. No
  async task queue; heavy work (LLM, WHOIS, attachment scan) is on the request path.
- **No horizontal scaling proven.** Single backend, SSE stream, no worker pool / autoscaling.
- **No GPU inference path.** Real throughput needs GPU or a hosted model API.

### 2.3 Detection quality
- **Validated on a semi-synthetic dataset.** The 1M rows use real domains but templated
  bodies; real-world mail is messier. Auto-quarantine must be validated on real production
  mail (with a human-review phase) before it can be trusted.
- **The 1M dataset is not used to train the model** — it validates the deterministic layer.
  A real CPU-trainable ML classifier (TF-IDF + logistic regression) on the 1M is designed but
  **deferred** (see §5).
- **Uzbek technical depth is limited** in the multilingual 7b variant (base-model constraint).

### 2.4 Product & commercial
- No self-serve **signup / tenant provisioning / onboarding**.
- No **billing / subscription / plans / metering**.
- No **admin/operator console** for the SaaS operator (tenant management, usage, health).

### 2.5 Compliance, data & legal
- Stores **email content (PII)** with no retention policy, data-residency options, export/delete
  (GDPR/DSAR), or encryption-at-rest for message bodies.
- Ships a **live phishing framework (GoPhish) + open mail server** — abuse/legal controls and
  authorized-use enforcement are required before hosting for others.
- No SOC 2 / ISO 27001 posture, DPA, audit logging completeness, or pen-test.

### 2.6 Operations & reliability
- No backups / disaster recovery / restore runbook.
- No alerting on the metrics, no centralized logging, no on-call/SLO definition.
- No blue/green or zero-downtime deploy; migrations run at startup (fine for one node, risky
  for many).

### 2.7 Frontend / UX
- Single vanilla dashboard (`frontend/`) is the shipping UI; the `frontend-react/` port is
  kept but not run. A production SaaS wants one maintained SPA with a design system, a11y,
  and an operator portal separate from the tenant app.

---

## 3. Phased roadmap

### Phase 0 — Production hardening (unlocks a single-org pilot) — ~2–4 weeks
- [x] Remove `--reload`; run Uvicorn/Gunicorn with multiple workers behind the Caddy/nginx TLS proxy.
- [x] Force non-default secrets on boot (`THREATEYE_AUTH_SECRET`, DB password); fail closed if defaults.
- [ ] Force an admin-password change on first login; drop `admin/admin`.
- [ ] `COOKIE_SECURE=true` + TLS as the default deployment path; HSTS.
- [x] Encrypt settings secrets at rest (Fernet/KMS); key management documented.
- [ ] Egress allow-list for `test-imap`/`test-siem`/URL-analyzer/WHOIS (kill the open SSRF).
- [ ] Backups + restore runbook for Postgres; metrics alerting.

### Phase 1 — True multi-tenant SaaS (unlocks external customers) — ~1–3 months
- [x] **Complete tenant isolation**: every read/write scoped by `organization_id`, enforced at
      a query layer (row-level security in Postgres, or a scoped repository), plus automated
      cross-tenant tests. Audit each endpoint (start with §2.1 list).
- [ ] Self-serve **signup + tenant provisioning** (isolated schema/row-scoped data, seed defaults).
- [ ] **Billing** (Stripe): plans, metering (emails scanned, seats, simulations), quotas,
      usage-based limits on `/v1/emails`.
- [ ] **Operator console**: manage tenants, suspend/impersonate (audited), usage & health.
- [x] Per-tenant **rate limits & quotas**; abuse detection.
- [ ] Async **task queue** (Celery/RQ/Arq) for LLM/WHOIS/attachment; request returns fast,
      verdict streams in. Optional GPU inference workers or a hosted model API.

### Phase 2 — Enterprise-grade — ~2–4 months
- [ ] **SSO** (SAML/OIDC), SCIM provisioning, MFA for operators/tenant admins.
- [ ] **Data governance**: retention policies, data residency (region pinning), DSAR
      export/delete, encryption-at-rest for message bodies, configurable PII redaction.
- [ ] Native **mail-gateway integrations**: Microsoft 365 / Google Workspace journaling or
      Graph API pull (beyond IMAP), so it drops into real mail flow.
- [ ] **Complete audit trail** + tamper-evidence; admin action logging.
- [ ] Compliance program: SOC 2 Type II / ISO 27001 roadmap, DPA templates, sub-processor list,
      third-party pen-test, responsible-disclosure/bug-bounty.
- [ ] Model governance: versioning, eval harness gating, drift monitoring, rollback.

### Phase 3 — Scale & global go-to-market — ~ongoing
- [ ] Horizontal scale: stateless backend + workers, read replicas, autoscaling, multi-region.
- [ ] Zero-downtime deploys; migrations decoupled from boot; blue/green.
- [ ] **Localization/i18n** of the UI (the model already handles EN/RU/UZ chat).
- [ ] Marketplace listings (Microsoft, Google, AWS), partner/reseller program.
- [ ] Status page, SLAs, 24/7 support tiers, customer success.
- [ ] Analytics & reporting exports (board-ready security posture reports).

---

## 4. Detailed backlog by area (pick-up list)

**Security**
- Row-level security in Postgres per `organization_id`.
- Secret encryption at rest; rotate keys.
- SSRF broker / egress allow-list; per-tenant outbound controls.
- Full CSP on the dashboard; subresource integrity; dependency scanning (SCA) in CI.
- Session hardening: device binding, revoke-all, suspicious-login alerts.

**Detection & AI/ML** (see §5)
- Train the CPU ML classifier on the 1M dataset; wire as a third detection layer.
- GPU LoRA fine-tune of the base model on real labeled mail; eval-gated promotion.
- Continuous evaluation harness + drift/regression dashboard; per-tenant model tuning.
- Real-mail validation of auto-quarantine with a human-in-the-loop shadow mode first.

**Performance**
- Async queue; batch LLM calls; cache verdicts by content hash.
- Model serving: vLLM/llama.cpp server, GPU pool, or hosted API fallback.

**Product / commercial**
- Signup, onboarding wizard, tenant settings, seat management.
- Billing, metering, plan gates, invoices, dunning.
- Operator/admin portal; usage analytics; feature flags.

**Compliance / data**
- Retention & residency; DSAR; encryption-at-rest for bodies; PII redaction toggles.
- Audit-log completeness + export; legal (ToS, DPA, AUP for the phishing framework).

**Ops**
- Backups/DR, alerting, centralized logs, SLOs, on-call, runbooks.
- IaC (Terraform), CI/CD to staging+prod, secrets manager, container scanning.

**Frontend / UX**
- Consolidate on one maintained SPA + design system + a11y; separate operator portal.
- Onboarding, empty states, guided setup, in-app docs.

---

## 5. AI / ML roadmap (specific)

The current model is **prompt/parameter specialisation** on a 1,210-technique corpus — not
gradient fine-tuning — which is why it runs on CPU. Paths to make the AI stronger:

1. **CPU ML classifier (near-term, no GPU).** Train a TF-IDF + logistic-regression / gradient-
   boosting classifier on the 1M labeled dataset (minutes on CPU). Real training on real text;
   adds an independent signal to the deterministic + LLM layers. *Designed, deferred by choice.*
2. **GPU LoRA fine-tune (mid-term).** Fine-tune the base (qwen2.5:7b or larger) on real labeled
   mail with LoRA on a GPU; import the merged GGUF into Ollama. Gate promotion on the eval
   harness. Needs a GPU box or cloud (Colab/A100).
3. **Retrieval augmentation.** Per-tenant threat-intel + historical verdicts as retrieval
   context, so the model adapts to each customer without retraining.
4. **Bigger / multilingual base for chat.** Uzbek technical depth needs a larger base or an
   Uzbek-tuned model; keep the fast 3b as the default scorer, offer 7b+ for the copilot.
5. **Governed self-improvement** (`scripts/self_improve.py`) is already bounded (analyst-
   confirmed data only, validation + safety gate, human `--confirm`, version ceiling, kill-
   switch). Extend with per-tenant candidates and automatic eval gating.

---

## 6. "Definition of done" for a SaaS launch (gate)

Do **not** onboard external paying tenants until all of these are true:

- [ ] Tenant isolation complete and covered by automated cross-tenant tests.
- [ ] Secrets encrypted at rest; no default credentials; TLS enforced; `--reload` removed.
- [ ] Async processing so a request never blocks on the LLM; per-tenant quotas/rate limits.
- [ ] Signup, billing, and an operator console exist.
- [ ] Data retention/residency/DSAR and encryption of message bodies implemented.
- [ ] Backups + DR tested; alerting + on-call in place.
- [ ] Independent security review / pen-test passed; SECURITY.md limitations closed.
- [ ] Auto-quarantine validated on real mail in shadow mode before enforcing.

---

*Keep this file updated as items land. Prefix issues/PRs with the phase (e.g. `P1: complete
tenant scoping on /cases`). The near-term critical path is: **tenant isolation → secrets &
hardening → async queue → billing/onboarding**.*
