import { useEffect, useState } from "react";
import { api, type Stats } from "../lib/api";

function Tile({ label, value, accent }: { label: string; value: number | string; accent: string }) {
  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-xl p-5">
      <p className="text-gray-400 text-sm mb-1">{label}</p>
      <h3 className={`text-3xl font-bold ${accent}`}>{value}</h3>
    </div>
  );
}

export function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.stats().then(setStats).catch(() => setError("Failed to load stats"));
  }, []);

  return (
    <div>
      <h2 className="text-2xl font-bold text-white mb-6">Security Dashboard</h2>
      {error && <p className="text-cyber-danger mb-4">{error}</p>}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Tile label="Total Emails Scanned" value={stats?.total_emails_scanned ?? "—"} accent="text-white" />
        <Tile label="Suspicious Emails" value={stats?.suspicious_emails ?? "—"} accent="text-cyber-warning" />
        <Tile label="Quarantined" value={stats?.quarantined_emails ?? "—"} accent="text-cyber-danger" />
        <Tile label="Active Simulations" value={stats?.active_simulations ?? "—"} accent="text-cyber-neon" />
      </div>
      <div className="mt-6 text-sm text-gray-500">
        Current risk level: <span className="text-cyber-neon font-bold">{stats?.current_risk_level ?? "—"}</span>
      </div>
    </div>
  );
}
