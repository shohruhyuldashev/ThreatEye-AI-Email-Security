import { useState, type FormEvent } from "react";
import { api } from "../lib/api";

interface Turn {
  who: "You" | "Copilot";
  text: string;
}

export function SocCenter() {
  const [log, setLog] = useState<Turn[]>([]);
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);

  async function ask(e: FormEvent) {
    e.preventDefault();
    if (!q.trim()) return;
    const question = q.trim();
    setLog((l) => [...l, { who: "You", text: question }]);
    setQ("");
    setBusy(true);
    try {
      const res = await api.copilot(question);
      setLog((l) => [...l, { who: "Copilot", text: res.answer }]);
    } catch {
      setLog((l) => [...l, { who: "Copilot", text: "Failed to reach the copilot." }]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h2 className="text-2xl font-bold text-white mb-6">SOC Center</h2>
      <div className="bg-cyber-panel border border-cyber-border rounded-xl p-6 max-w-3xl">
        <h3 className="text-lg font-semibold text-white mb-4">AI SOC Copilot</h3>
        <div className="space-y-3 mb-4 max-h-80 overflow-y-auto">
          {log.map((t, i) => (
            <div key={i}>
              <div className="text-xs text-gray-500">{t.who}</div>
              <div className={`whitespace-pre-wrap ${t.who === "Copilot" ? "text-cyber-neon" : "text-gray-300"}`}>
                {t.text}
              </div>
            </div>
          ))}
          {busy && <div className="text-xs text-gray-500">Copilot is thinking…</div>}
        </div>
        <form onSubmit={ask} className="flex gap-3">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Ask about your detections…"
            className="flex-1 rounded-lg px-4 py-2 bg-cyber-dark border border-cyber-border text-gray-200"
          />
          <button className="py-2 px-4 bg-cyber-neon/10 border border-cyber-neon text-cyber-neon rounded-lg">
            Ask
          </button>
        </form>
      </div>
      <p className="text-xs text-gray-600 mt-6">
        This React app is the migration target — the full feature set still lives in <code>frontend/</code>.
      </p>
    </div>
  );
}
