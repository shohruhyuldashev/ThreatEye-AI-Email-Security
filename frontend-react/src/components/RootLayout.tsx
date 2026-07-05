import { Suspense } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../lib/auth";
import { APP_ROUTES, canAccess } from "../routes";
import { NotificationBell } from "./NotificationBell";

/**
 * The layout route: renders once and swaps only the matched child via <Outlet/>.
 * The sidebar is generated from the same route table, filtered by the user's role.
 */
export function RootLayout() {
  const { identity, logout } = useAuth();
  const nav = APP_ROUTES.filter((r) => canAccess(r, identity?.role));

  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `flex items-center gap-2 px-4 py-3 text-sm rounded-lg transition-colors ${
      isActive ? "bg-cyber-neon/10 text-cyber-neon" : "text-gray-400 hover:text-white"
    }`;

  return (
    <div className="flex h-screen">
      <aside className="w-64 bg-cyber-panel border-r border-cyber-border flex flex-col">
        <div className="h-16 flex items-center px-6 border-b border-cyber-border text-white font-semibold text-lg">
          Threat<span className="text-cyber-neon">Eye</span>
        </div>
        <nav className="flex-1 px-4 py-6 space-y-2 overflow-y-auto">
          {nav.map((r) => (
            <NavLink key={r.path} to={r.path} end={r.index} className={linkClass}>
              <span aria-hidden>{r.icon}</span>
              {r.label}
            </NavLink>
          ))}
        </nav>
        <div className="p-4 border-t border-cyber-border">
          <div className="text-xs text-white">{identity?.username}</div>
          <div className="text-[10px] text-gray-500 mb-3 capitalize">{identity?.role}</div>
          <button
            onClick={logout}
            className="w-full py-1.5 text-xs text-gray-400 hover:text-cyber-danger border border-cyber-border rounded"
          >
            Log Out
          </button>
        </div>
      </aside>
      <main className="flex-1 flex flex-col min-w-0">
        <header className="h-16 flex items-center justify-end px-8 border-b border-cyber-border/60 bg-cyber-dark/50">
          <NotificationBell />
        </header>
        <div className="flex-1 overflow-y-auto p-8">
          <Suspense fallback={<div className="text-gray-500">Loading…</div>}>
            <Outlet />
          </Suspense>
        </div>
      </main>
    </div>
  );
}
