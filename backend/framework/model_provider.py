"""
LLM provider resolution.

The active model is configured from the GUI (Settings → AI Engine) and stored in the
`settings` table, falling back to environment variables. Any OpenAI-compatible
provider works through the same client — OpenAI, Anthropic (OpenAI-compat endpoint),
Groq, a local Ollama, or a custom base URL — so switching providers is just changing
settings, no redeploy. Resolved fresh on each call so GUI changes take effect live.
"""
import os

from openai import OpenAI

from db import get_db_connection

# provider → default base URL + a sensible default model.
PROVIDER_PRESETS = {
    "ollama":    {"base_url": "http://ollama:11434/v1",       "default_model": "llama3.2",                "needs_key": False},
    "openai":    {"base_url": "https://api.openai.com/v1",    "default_model": "gpt-4o-mini",             "needs_key": True},
    "anthropic": {"base_url": "https://api.anthropic.com/v1", "default_model": "claude-3-5-haiku-latest", "needs_key": True},
    "groq":      {"base_url": "https://api.groq.com/openai/v1", "default_model": "llama-3.1-8b-instant",  "needs_key": True},
    "custom":    {"base_url": "",                             "default_model": "",                        "needs_key": False},
}

# Generous default: local models on CPU can take 30–60s for the full SOC prompt.
# Tune with LLM_TIMEOUT (seconds).
LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "90"))


def _settings(keys: list[str]) -> dict:
    try:
        conn = get_db_connection()
        c = conn.cursor()
        placeholders = ",".join(["?"] * len(keys))
        c.execute(f"SELECT key, value FROM settings WHERE key IN ({placeholders})", tuple(keys))
        rows = {r["key"]: r["value"] for r in c.fetchall()}
        conn.close()
        return rows
    except Exception:
        return {}


def resolve_ai_config() -> dict:
    """Resolve the effective provider/base_url/api_key/model from settings, then env, then presets."""
    s = _settings(["ai_provider", "ai_api_key", "ai_base_url", "ai_model"])
    provider = (s.get("ai_provider") or os.getenv("AI_PROVIDER", "ollama")).lower()
    preset = PROVIDER_PRESETS.get(provider, PROVIDER_PRESETS["custom"])

    base_url = s.get("ai_base_url") or preset["base_url"] or os.getenv("OPENAI_API_BASE", "http://ollama:11434/v1")
    api_key = s.get("ai_api_key") or os.getenv("OPENAI_API_KEY") or ""
    if not api_key:
        # The OpenAI SDK requires a non-empty key even for keyless local servers.
        api_key = "ollama" if provider == "ollama" else "not-needed"
    model = s.get("ai_model") or os.getenv("AI_MODEL") or preset["default_model"] or "llama3.2"
    return {"provider": provider, "base_url": base_url, "api_key": api_key, "model": model}


def get_llm_client() -> OpenAI:
    cfg = resolve_ai_config()
    return OpenAI(api_key=cfg["api_key"], base_url=cfg["base_url"], timeout=LLM_TIMEOUT, max_retries=1)


def get_model_name() -> str:
    return resolve_ai_config()["model"]
