import { useEffect, useState } from "react";
import { api, type Email } from "../lib/api";

export function Quarantine() {
  const [items, setItems] = useState<Email[]>([]);
  useEffect(() => {
    api.quarantine().then(setItems).catch(() => setItems([]));
  }, []);

  return (
    <div>
      <h2 className="text-2xl font-bold text-white mb-6">Quarantine</h2>
      <div className="bg-cyber-panel border border-cyber-border rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-xs text-gray-500 uppercase border-b border-cyber-border">
            <tr>
              <th className="text-left p-4">Sender</th>
              <th className="text-left p-4">Subject</th>
              <th className="text-left p-4">Threat</th>
              <th className="text-left p-4">Risk</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 && (
              <tr><td colSpan={4} className="p-6 text-center text-gray-500">No threats isolated.</td></tr>
            )}
            {items.map((e) => (
              <tr key={e.id} className="border-b border-cyber-border/40">
                <td className="p-4 text-white truncate max-w-[220px]">{e.sender}</td>
                <td className="p-4 text-gray-300 truncate max-w-[280px]">{e.subject}</td>
                <td className="p-4 text-gray-400">{e.threat_type}</td>
                <td className="p-4 font-bold text-cyber-danger">{e.risk_score}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
