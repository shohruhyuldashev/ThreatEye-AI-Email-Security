// Typed API client — cookie-based JWT sessions (httpOnly access/refresh cookies).
// No token in JS/localStorage: the browser sends the cookies automatically. For
// mutating requests we echo the readable `csrf_token` cookie in an X-CSRF-Token
// header (double-submit CSRF), and transparently refresh the access token on 401.

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function csrfToken(): string {
  const m = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

// Single-flight refresh so concurrent 401s trigger only one /auth/refresh.
let refreshing: Promise<boolean> | null = null;
function tryRefresh(): Promise<boolean> {
  if (!refreshing) {
    refreshing = fetch("/api/auth/refresh", {
      method: "POST",
      credentials: "include",
      headers: { "X-CSRF-Token": csrfToken() },
    })
      .then((r) => r.ok)
      .catch(() => false)
      .finally(() => {
        refreshing = null;
      });
  }
  return refreshing;
}

async function raw(path: string, options: RequestInit): Promise<Response> {
  const headers = new Headers(options.headers || {});
  const method = (options.method || "GET").toUpperCase();
  if (MUTATING.has(method)) headers.set("X-CSRF-Token", csrfToken());
  if (options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  return fetch(`/api${path}`, { ...options, headers, credentials: "include" });
}

async function request<T>(path: string, options: RequestInit = {}, retry = true): Promise<T> {
  let res = await raw(path, options);
  if (res.status === 401 && retry && !path.startsWith("/auth/")) {
    if (await tryRefresh()) res = await raw(path, options);
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export interface Identity {
  username: string;
  role: string;
  organization_id: number;
}
export interface Stats {
  total_emails_scanned: number;
  suspicious_emails: number;
  quarantined_emails: number;
  active_simulations: number;
  current_risk_level: number;
}
export interface Email {
  id: number;
  sender: string;
  subject: string;
  risk_score: number;
  url_threat_score: number;
  status: string;
  threat_type: string;
  timestamp: string;
}

export interface Plugin {
  plugin_id: string;
  name: string;
  version: string;
  author: string;
  category: string;
  description: string;
  enabled: boolean;
  signed: boolean;
  counts: { rules?: number; intel?: number; playbooks?: number };
}
export interface Notification {
  type: string;
  time: string;
  subject: string;
  details: string;
  email_id: number | null;
}
export interface User {
  id: number;
  username: string;
  email: string;
  full_name: string;
  role: string;
  active: boolean;
}
export interface ApiKey {
  id: number;
  name: string;
  active: boolean;
  last_used_at: string | null;
}

function upload<T>(path: string, file: File): Promise<T> {
  const fd = new FormData();
  fd.append("file", file);
  return request<T>(path, { method: "POST", body: fd });
}

export const api = {
  login: (username: string, password: string) =>
    request<{ user: Identity }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request<{ message: string }>("/auth/logout", { method: "POST" }),
  me: () => request<Identity>("/auth/me"),
  stats: (days = 7) => request<Stats>(`/stats?days=${days}`),
  emails: (limit = 50) => request<Email[]>(`/emails?limit=${limit}`),
  quarantine: () => request<Email[]>("/quarantine"),
  notifications: () => request<Notification[]>("/notifications"),
  socMetrics: () => request<Record<string, unknown>>("/soc/metrics"),
  copilot: (question: string) =>
    request<{ answer: string }>("/copilot", { method: "POST", body: JSON.stringify({ question }) }),

  // Plugins (.tap)
  plugins: () => request<Plugin[]>("/plugins"),
  uploadPlugin: (file: File) => upload<{ name: string; installed: Record<string, number> }>("/plugins/upload", file),
  togglePlugin: (id: string, enabled: boolean) =>
    request(`/plugins/${encodeURIComponent(id)}/toggle`, { method: "POST", body: JSON.stringify({ enabled }) }),
  removePlugin: (id: string) => request(`/plugins/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // Team
  users: () => request<User[]>("/users"),
  createUser: (body: { username: string; password: string; role: string; full_name?: string }) =>
    request<{ id: number }>("/users", { method: "POST", body: JSON.stringify(body) }),
  deleteUser: (id: number) => request(`/users/${id}`, { method: "DELETE" }),
  apiKeys: () => request<ApiKey[]>("/keys"),
  createApiKey: (name: string) =>
    request<{ api_key: string; name: string }>("/keys", { method: "POST", body: JSON.stringify({ name }) }),
  revokeApiKey: (id: number) => request(`/keys/${id}`, { method: "DELETE" }),
};
