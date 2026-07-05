# Security notes — ThreatEye

ThreatEye is a **security lab / research platform**. It ships GoPhish (a live phishing
framework) and an open mail server, so treat every deployment as sensitive and keep it
on an isolated network. This document lists the hardening that is built in, what you
must still configure, and the known limitations of the lab defaults.

## Hardening built into the app

| Area | Control |
|------|---------|
| Login brute force | Per-IP sliding-window rate limit on `/api/auth/login` (`THREATEYE_LOGIN_MAX_ATTEMPTS` / `THREATEYE_LOGIN_WINDOW_SECONDS`), plus `login_success` / `login_failed` audit-log entries. |
| Credential errors | Wrong username and wrong password return the **same** generic `401`, so the endpoint doesn't reveal which field was wrong. |
| Password storage | Admin password stored as PBKDF2-HMAC-SHA256 (200k iterations, per-hash salt); a legacy plaintext/default value is migrated to a hash on first successful login. |
| Session tokens | HMAC-SHA256 signed, with an `exp` claim; verified in constant time. Signing secret comes from `THREATEYE_AUTH_SECRET`, or is auto-generated and persisted so it is random rather than a shipped default. |
| Secret exposure | `admin_password` and `auth_secret` are never returned by `GET /api/settings`; other `*pass*/*key*/*secret*/*token*` settings are masked. |
| HTTP headers | `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store` on API responses (see `SecurityHeadersMiddleware`). |
| CORS | Explicit origin allow-list, credentials disabled (the API is bearer-token based), methods/headers restricted. |
| Uploads | Target files are extension-restricted (`.txt` / `.csv`), filename-sanitised, randomly renamed, and capped at 1 MB. |
| SQL | All queries are parameterised; the few dynamic identifiers come from hard-coded allow-lists, not user input. |
| Output rendering | Frontend HTML-escapes all attacker-influenced fields (sender, subject, evidence, timeline) before injecting them into the DOM. |
| Network exposure | `docker-compose.yml` binds Postgres and Ollama to `127.0.0.1` only. |

## You MUST configure before any real use

1. **Change the admin password.** The default is `admin`. Log in and change it, or set a
   PBKDF2 hash in the `admin_password` setting.
2. **Set strong secrets in `.env`** (copy from `.env.example`): `THREATEYE_AUTH_SECRET`
   and `POSTGRES_PASSWORD`.
3. **Restrict `CORS_ALLOWED_ORIGINS`** to the exact dashboard origin.
4. **Put the dashboard/API behind TLS** (a reverse proxy such as Caddy/Traefik/nginx).
   Tokens are bearer tokens; without TLS they can be sniffed.

## Multi-tenancy & RBAC (1.4.0)

- Users live in a `users` table with four roles (`viewer` < `analyst` < `admin` < `owner`);
  endpoints are role-gated and reads/writes are scoped by `organization_id`.
- Machine clients authenticate to `POST /api/v1/emails` with a per-tenant `X-API-Key`
  (stored only as a SHA-256 hash; the plaintext is shown once at creation).
- Protections: no self-lockout/self-delete, last-owner cannot be removed, only an owner
  can grant `owner`, and API keys can be revoked.

## Known limitations (acceptable for a lab, fix before production)

- **Session token in `localStorage`.** A stored XSS would expose the token. Output
  escaping mitigates this, but a strict CSP and moving to `httpOnly` cookies would be
  the production-grade fix.
- **Per-tenant read scoping is partial.** The core data paths (stats, emails, quarantine,
  live stream) are tenant-scoped; some secondary read endpoints (iocs, mitre, audit-log,
  cases, siem-events) still default to the primary org and should be scoped before onboarding
  a second real tenant.
- **Admin-authenticated SSRF surface.** `POST /api/settings/test-imap` and the URL
  analyzer / WHOIS lookups reach arbitrary hosts. This is intended (it's how the lab
  connects to mail servers) but means an admin token is powerful — keep the instance
  isolated.
- **`--reload` in the backend Dockerfile** is a development convenience (source is bind-
  mounted). Remove it and run multiple workers for a real deployment.
- **GoPhish and the mail server** are full-featured; only run them on a lab network you
  control and are authorised to test.

## Reporting

This is a personal lab project — open an issue or note findings in `CHANGELOG.md`.
