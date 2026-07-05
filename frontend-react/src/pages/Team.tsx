import { useEffect, useState, type FormEvent } from "react";
import { api, type User, type ApiKey } from "../lib/api";

export function Team() {
  const [users, setUsers] = useState<User[]>([]);
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [newKey, setNewKey] = useState<string | null>(null);
  const [err, setErr] = useState("");

  async function load() {
    try {
      setUsers(await api.users());
      setKeys(await api.apiKeys());
    } catch {
      setErr("Requires admin role to manage the team.");
    }
  }
  useEffect(() => {
    load();
  }, []);

  async function addUser(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = e.currentTarget;
    const data = new FormData(f);
    try {
      await api.createUser({
        username: String(data.get("username")),
        password: String(data.get("password")),
        role: String(data.get("role")),
        full_name: String(data.get("full_name") || ""),
      });
      f.reset();
      load();
    } catch (e2) {
      setErr((e2 as Error).message);
    }
  }

  async function addKey(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = e.currentTarget;
    const name = String(new FormData(f).get("name"));
    try {
      const res = await api.createApiKey(name);
      setNewKey(res.api_key);
      f.reset();
      load();
    } catch (e2) {
      setErr((e2 as Error).message);
    }
  }

  return (
    <div>
      <h2 className="text-2xl font-bold text-white mb-6">Team &amp; Access</h2>
      {err && <p className="text-cyber-danger text-sm mb-4">{err}</p>}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        <div className="bg-cyber-panel border border-cyber-border rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Users</h3>
          <form onSubmit={addUser} className="grid grid-cols-2 gap-3 mb-4">
            <input name="username" placeholder="username" required className="rounded px-3 py-2 bg-cyber-dark border border-cyber-border text-sm text-gray-200" />
            <input name="password" type="password" placeholder="password (min 8)" required className="rounded px-3 py-2 bg-cyber-dark border border-cyber-border text-sm text-gray-200" />
            <input name="full_name" placeholder="full name" className="rounded px-3 py-2 bg-cyber-dark border border-cyber-border text-sm text-gray-200" />
            <select name="role" className="rounded px-3 py-2 bg-cyber-dark border border-cyber-border text-sm text-gray-200">
              <option value="viewer">viewer</option>
              <option value="analyst">analyst</option>
              <option value="admin">admin</option>
              <option value="owner">owner</option>
            </select>
            <button className="col-span-2 py-2 bg-cyber-neon/10 border border-cyber-neon text-cyber-neon rounded text-sm">Add User</button>
          </form>
          <div className="space-y-1">
            {users.map((u) => (
              <div key={u.id} className="flex justify-between items-center text-sm py-2 border-b border-cyber-border/40">
                <span className="text-white">{u.username} <span className="text-gray-600 text-xs">{u.role}</span></span>
                <button onClick={() => api.deleteUser(u.id).then(load)} className="text-xs text-gray-500 hover:text-cyber-danger">Delete</button>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-cyber-panel border border-cyber-border rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4">API Keys</h3>
          <form onSubmit={addKey} className="flex gap-3 mb-4">
            <input name="name" placeholder="key name" required className="flex-1 rounded px-3 py-2 bg-cyber-dark border border-cyber-border text-sm text-gray-200" />
            <button className="py-2 px-4 bg-cyber-warning/10 border border-cyber-warning text-cyber-warning rounded text-sm">Generate</button>
          </form>
          {newKey && (
            <div className="mb-4 p-3 rounded bg-cyber-dark border border-cyber-neon/40 text-xs break-all text-cyber-neon">
              Copy now — shown once: {newKey}
            </div>
          )}
          <div className="space-y-1">
            {keys.map((k) => (
              <div key={k.id} className="flex justify-between items-center text-sm py-2 border-b border-cyber-border/40">
                <span className="text-white">{k.name} <span className={k.active ? "text-cyber-neon text-xs" : "text-gray-600 text-xs"}>{k.active ? "active" : "revoked"}</span></span>
                {k.active && <button onClick={() => api.revokeApiKey(k.id).then(load)} className="text-xs text-gray-500 hover:text-cyber-danger">Revoke</button>}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
