import contextlib
import logging
import os
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from api.router import router as api_router
from services.scheduler import start_scheduler, shutdown_scheduler
import threading
from services.email_watcher import start_email_watcher
from framework.policy_engine import seed_default_policies
from framework.playbooks import seed_default_playbooks
from framework.rules import load_detection_rules
from framework.migrations import run_migrations, seed_saas_defaults
from framework import metrics

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

VERSION = "1.14.0"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds baseline hardening headers to every response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-XSS-Protection", "0")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        response.headers.setdefault(
            "Cache-Control", "no-store" if request.url.path.startswith("/api") else "no-cache"
        )
        return response


class MetricsMiddleware(BaseHTTPMiddleware):
    """Records request count + latency by method / route template / status."""

    async def dispatch(self, request: Request, call_next):
        timer = metrics.MetricsTimer(request.method, request.url.path)
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            # Prefer the matched route template to keep label cardinality low.
            route = request.scope.get("route")
            timer.path = getattr(route, "path", request.url.path)
            timer.done(status)


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    Double-submit CSRF protection for cookie-based sessions. On a mutating request
    that carries the access-token cookie (i.e. a browser session), require the
    X-CSRF-Token header to match the readable `csrf_token` cookie. Header/API-key
    clients (no auth cookie) are exempt — they aren't vulnerable to CSRF. Login is
    exempt (it bootstraps the session).
    """

    _MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
    _EXEMPT = {"/api/auth/login"}

    async def dispatch(self, request: Request, call_next):
        if request.method in self._MUTATING and request.url.path not in self._EXEMPT:
            if request.cookies.get("access_token"):
                cookie = request.cookies.get("csrf_token")
                header = request.headers.get("x-csrf-token")
                if not cookie or cookie != header:
                    from fastapi.responses import JSONResponse
                    return JSONResponse(status_code=403, content={"detail": "CSRF token missing or invalid"})
        return await call_next(request)

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: apply schema migrations + seed multi-tenant defaults first,
    # then the detection content and background tasks.
    run_migrations()
    seed_saas_defaults()
    seed_default_policies()
    seed_default_playbooks()
    load_detection_rules()
    start_scheduler()
    
    # Start the continuous IMAP IDLE watcher in a daemon thread
    watcher_thread = threading.Thread(target=start_email_watcher, daemon=True, name="IMAP_IDLE_Watcher")
    watcher_thread.start()
    
    yield
    # Shutdown: Cleanly stop background tasks
    shutdown_scheduler()

app = FastAPI(title="ThreatEye AI Email Security API", version=VERSION, lifespan=lifespan)
allowed_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
    if origin.strip()
]

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(MetricsMiddleware)
app.add_middleware(CSRFMiddleware)

# CORS is added LAST so it is the outermost middleware (handles preflight and wraps
# CSRF responses with the right headers). The session uses cookies, so credentials
# are allowed and origins must be explicit (never "*").
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-API-Key"],
    max_age=600,
)

app.include_router(api_router, prefix="/api")


@app.get("/health")
def health():
    """Lightweight liveness probe (no auth, no DB round-trip)."""
    return {"status": "ok", "service": "threateye", "version": VERSION}


@app.get("/ready")
def ready():
    """Readiness probe — verifies the database is reachable."""
    from db import get_db_connection
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT 1")
        c.fetchone()
        conn.close()
        return {"status": "ready", "database": "ok"}
    except Exception as e:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=503, content={"status": "not_ready", "error": str(e)})


@app.get("/metrics")
def prometheus_metrics():
    """Prometheus scrape endpoint (dependency-free text exposition)."""
    return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")


if __name__ == "__main__":
    import uvicorn

    # reload defaults off; enable explicitly with DEV_RELOAD=1 for local development.
    dev_reload = os.getenv("DEV_RELOAD", "0").lower() in {"1", "true", "yes", "on"}
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=dev_reload)
