import { useEffect, useState } from "react";
import { api, type Email } from "../lib/api";

export function Monitor() {
  const [emails, setEmails] = useState<Email[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    api.emails(50).then(setEmails).catch(() => setError("Failed to load emails"));
  }, []);

  return (
    <div>
      <h2 className="text-2xl font-bold text-white mb-6">Real-Time Monitor</h2>
      {error && <p className="text-cyber-danger mb-4">{error}</p>}
      <div className="bg-cyber-panel border border-cyber-border rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-xs text-gray-500 uppercase border-b border-cyber-border">
            <tr>
              <th className="text-left p-4">Sender</th>
              <th className="text-left p-4">Subject</th>
              <th className="text-left p-4">Type</th>
              <th className="text-left p-4">Risk</th>
              <th className="text-left p-4">Status</th>
            </tr>
          </thead>
          <tbody>
            {emails.length === 0 && (
              <tr><td colSpan={5} className="p-6 text-center text-gray-500">No emails monitored yet.</td></tr>
            )}
            {emails.map((e) => (
              <tr key={e.id} className="border-b border-cyber-border/40">
                <td className="p-4 text-white truncate max-w-[220px]">{e.sender}</td>
                <td className="p-4 text-gray-300 truncate max-w-[280px]">{e.subject}</td>
                <td className="p-4 text-gray-400">{e.threat_type}</td>
                <td className={`p-4 font-bold ${e.risk_score > 70 ? "text-cyber-danger" : "text-cyber-neon"}`}>
                  {e.risk_score}%
                </td>
                <td className="p-4">
                  <span
                    className={`text-xs px-2 py-0.5 rounded ${
                      e.status === "Quarantined"
                        ? "bg-cyber-danger/20 text-cyber-danger"
                        : "bg-cyber-neon/10 text-cyber-neon"
                    }`}
                  >
                    {e.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
