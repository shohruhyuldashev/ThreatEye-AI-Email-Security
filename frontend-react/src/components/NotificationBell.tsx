import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, type Notification } from "../lib/api";

export function NotificationBell() {
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<Notification[]>([]);
  const navigate = useNavigate();
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.notifications().then(setItems).catch(() => setItems([]));
    const onDocClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("click", onDocClick);
    return () => document.removeEventListener("click", onDocClick);
  }, []);

  // Clicking a notification navigates to the relevant item.
  function openItem(n: Notification) {
    setOpen(false);
    navigate("/quarantine", { state: { focusEmailId: n.email_id } });
  }

  return (
    <div className="relative" ref={ref}>
      <button onClick={() => setOpen((o) => !o)} className="relative p-2 text-gray-400 hover:text-white">
        <span aria-hidden>🔔</span>
        {items.length > 0 && (
          <span className="absolute top-1 right-1 w-2 h-2 bg-cyber-danger rounded-full" />
        )}
      </button>
      {open && (
        <div className="absolute right-0 mt-2 w-80 bg-cyber-panel border border-cyber-border rounded-lg shadow-xl z-50">
          <div className="p-3 border-b border-cyber-border/50 text-sm font-semibold text-white">Recent Alerts</div>
          <ul className="max-h-64 overflow-y-auto">
            {items.length === 0 && <li className="p-3 text-xs text-center text-gray-500">No new alerts</li>}
            {items.map((n, i) => (
              <li
                key={i}
                onClick={() => openItem(n)}
                className="p-3 border-b border-cyber-border/40 hover:bg-cyber-dark/60 cursor-pointer"
              >
                <p className="text-xs font-semibold text-white truncate">{n.subject}</p>
                <p className="text-[10px] text-gray-400 truncate">{n.details}</p>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
