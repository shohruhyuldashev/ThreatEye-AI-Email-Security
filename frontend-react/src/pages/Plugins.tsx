import { useEffect, useRef, useState } from "react";
import { api, type Plugin } from "../lib/api";

export function Plugins() {
  const [plugins, setPlugins] = useState<Plugin[]>([]);
  const [msg, setMsg] = useState<{ text: string; error?: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  async function load() {
    try {
      setPlugins(await api.plugins());
    } catch {
      setMsg({ text: "Failed to load plugins", error: true });
    }
  }
  useEffect(() => {
    load();
  }, []);

  async function onUpload(e: React.FormEvent) {
    e.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (!file) return;
    setBusy(true);
    setMsg(null);
    try {
      const res = await api.uploadPlugin(file);
      const c = res.installed || {};
      setMsg({ text: `Installed "${res.name}" — rules ${c.rules || 0}, intel ${c.intel || 0}, playbooks ${c.playbooks || 0}.` });
      if (fileRef.current) fileRef.current.value = "";
      load();
    } catch (err) {
      setMsg({ text: (err as Error).message, error: true });
    } finally {
      setBusy(false);
    }
  }

  async function toggle(p: Plugin) {
    await api.togglePlugin(p.plugin_id, !p.enabled).catch(() => {});
    load();
  }
  async function remove(p: Plugin) {
    if (!confirm(`Remove plugin "${p.plugin_id}" and all content it added?`)) return;
    await api.removePlugin(p.plugin_id).catch(() => {});
    load();
  }

  return (
    <div>
      <h2 className="text-2xl font-bold text-white mb-2">Detection Plugins</h2>
      <p className="text-sm text-gray-400 mb-6">
        Install <code className="text-cyber-neon">.tap</code> packs of detection rules, threat-intel and playbooks. Plugins
        are declarative — no code runs on the server.
      </p>

      <form onSubmit={onUpload} className="flex gap-3 mb-4 max-w-2xl">
        <input
          ref={fileRef}
          type="file"
          accept=".tap,.json"
          required
          className="flex-1 rounded-lg px-3 py-2 bg-cyber-dark border border-cyber-border text-sm text-gray-300"
        />
        <button
          disabled={busy}
          className="py-2 px-4 bg-cyber-info/10 border border-cyber-info text-cyber-info rounded-lg text-sm font-medium disabled:opacity-60"
        >
          {busy ? "Installing…" : "Install"}
        </button>
      </form>
      {msg && <p className={`text-sm mb-4 ${msg.error ? "text-cyber-danger" : "text-cyber-neon"}`}>{msg.text}</p>}

      <div className="space-y-2 max-w-3xl">
        {plugins.length === 0 && <div className="text-gray-500 text-sm">No plugins installed.</div>}
        {plugins.map((p) => (
          <div
            key={p.plugin_id}
            className="flex justify-between items-center p-4 rounded-lg bg-cyber-panel border border-cyber-border"
          >
            <div>
              <div className="text-white text-sm font-medium">
                {p.name} <span className="text-gray-600 text-xs">v{p.version}</span>{" "}
                <span
                  className={`text-[10px] px-2 py-0.5 rounded ${
                    p.signed ? "bg-cyber-neon/20 text-cyber-neon" : "bg-cyber-warning/20 text-cyber-warning"
                  }`}
                >
                  {p.signed ? "signed" : "unverified"}
                </span>
              </div>
              <div className="text-xs text-gray-500">{p.description}</div>
              <div className="text-[11px] text-gray-600 mt-1">
                by {p.author} · rules {p.counts.rules || 0} · intel {p.counts.intel || 0} · playbooks{" "}
                {p.counts.playbooks || 0}
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => toggle(p)}
                className={`text-xs px-2 py-1 rounded border ${
                  p.enabled ? "border-cyber-neon/40 text-cyber-neon" : "border-cyber-border text-gray-500"
                }`}
              >
                {p.enabled ? "Enabled" : "Disabled"}
              </button>
              <button onClick={() => remove(p)} className="text-xs px-2 py-1 rounded text-gray-400 hover:text-cyber-danger">
                Remove
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
