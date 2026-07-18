# Security notes — ThreatEye

ThreatEye is a **security lab / research platform**. It ships GoPhish (a live phishing
framework) and an open mail server, so treat every deployment as sensitive and keep it on
an isolated network you are authorised to test. This document lists the hardening that is
built in, what you must still configure, and the known limitations of the lab defaults.

## Hardening built into the app

| Area | Control |
|------|---------|
| Sessions | **JWT** (PyJWT, HS256) **access + refresh tokens in `httpOnly` cookies** — never in `localStorage`, so a stored XSS cannot read them. Access ~15 min, refresh ~7 days with **rotation + reuse detection** (a replayed refresh token is revoked). Signing key from `THREATEYE_AUTH_SECRET`, or auto-generated and persisted. |
| CSRF | Double-submit: a readable `csrf_token` cookie must be echoed in the `X-CSRF-Token` header on cookie-authenticated mutating requests (`CSRFMiddleware`); header/API-key clients and login are exempt. |
| Same-origin | The `:3000` dashboard proxies `/api` to the backend, so the browser sees one origin — no cross-origin cookie exposure and no permissive CORS needed for the UI. |
| Login brute force | Per-IP sliding-window rate limit on `/api/auth/login` (`THREATEYE_LOGIN_MAX_ATTEMPTS` / `THREATEYE_LOGIN_WINDOW_SECONDS`), Redis-backed across replicas, with `login_success` / `login_failed` audit entries. |
| Credential errors | Wrong username and wrong password return the **same** generic `401`. |
| Password storage | PBKDF2-HMAC-SHA256 (per-hash salt); a legacy plaintext/default value is migrated to a hash on first successful login. |
| Secret exposure | `admin_password` / `auth_secret` are never returned by `GET /api/settings`; other `*pass*/*key*/*secret*/*token*` settings (AI key, SIEM key, GoPhish key, Google SA JSON, …) are masked. |
| HTTP headers | `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store` on API responses. |
| CORS | Explicit origin allow-list; credentials enabled only for the configured dashboard origin(s) (`CORS_ALLOWED_ORIGINS`), methods/headers restricted, `X-CSRF-Token`/`X-API-Key` allowed. |
| Uploads | Extension-restricted (`.txt` / `.csv` / `.tap`), filename-sanitised, randomly renamed, size-capped. |
| SQL | All queries parameterised; the few dynamic identifiers come from hard-coded allow-lists, not user input. |
| Output rendering | The frontend HTML-escapes all attacker-influenced fields (sender, subject, evidence, timeline) before injecting them into the DOM. |
| Network exposure | `docker-compose.yml` binds Postgres, Redis and Ollama to `127.0.0.1` only. |
| SIEM delivery | Alerts are dispatched to a background worker (non-blocking) with retry + backoff; the destination + key are set in the admin panel, not hard-coded. |

## You MUST configure before any real use

1. **Change the admin password.** The default is `admin`.
2. **Set strong secrets in `.env`** (copy from `.env.example`): `THREATEYE_AUTH_SECRET`
   and `POSTGRES_PASSWORD`.
3. **Serve over TLS and set `COOKIE_SECURE=true`.** The session cookies are `httpOnly` but
   not `Secure` by default (so the lab works over plain HTTP); behind a real deployment,
   terminate TLS (Caddy/Traefik/nginx) and set `COOKIE_SECURE=true` + an appropriate
   `COOKIE_SAMESITE`.
4. **Restrict `CORS_ALLOWED_ORIGINS`** to the exact dashboard origin.

## Multi-tenancy & RBAC

- Users live in a `users` table with four roles (`viewer` < `analyst` < `admin` < `owner`);
  endpoints are role-gated and reads/writes are scoped by `organization_id`.
- Machine clients authenticate to `POST /api/v1/emails` with a per-tenant `X-API-Key`
  (stored only as a SHA-256 hash; the plaintext is shown once at creation and can be revoked).
- Protections: no self-lockout/self-delete, the last `owner` cannot be removed, only an
  owner can grant `owner`.

## Known limitations (acceptable for a lab, review before production)

- **Per-tenant read scoping is partial.** Core data paths (stats, emails, quarantine, live
  stream, simulations) are tenant-scoped; some secondary reads (iocs, mitre, audit-log,
  cases, siem-events) still default to the primary org and should be scoped before
  onboarding a second real tenant.
- **Admin-authenticated SSRF surface.** `POST /api/settings/test-imap`, `test-siem`, the URL
  analyzer and WHOIS lookups reach arbitrary hosts by design (that's how the lab connects to
  mail/SIEM servers) — an admin token is powerful, so keep the instance isolated.
- **`--reload` in the backend Dockerfile** is a development convenience (source is
  bind-mounted). Remove it and run multiple workers for a real deployment.
- **Bundled model weights are not signed.** `scripts/model-archive.sh` archives the Ollama
  volume; verify the source of any imported archive.
- **GoPhish and the mail server** are full-featured; only run them on a lab network you
  control and are authorised to test. Phishing simulations are for consenting employees /
  authorised engagements only.

## Reporting

This is a personal lab project — open an issue or note findings in `CHANGELOG.md`.
