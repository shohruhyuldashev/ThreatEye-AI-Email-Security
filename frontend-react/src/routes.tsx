import { lazy, type ComponentType } from "react";

/**
 * Central, logical route table — the single source of truth consumed by both the
 * router (main.tsx) and the sidebar nav (RootLayout). Each route declares its own
 * access rule (`roles`) and nav metadata, so authorization and navigation stay in
 * sync automatically. Pages are lazy-loaded, so each route ships as its own chunk.
 */
export interface AppRoute {
  path: string;
  label: string;
  icon: string;
  roles?: string[]; // allowed roles; omit = any authenticated user
  index?: boolean; // the "/" home route
  Component: ComponentType;
}

const Dashboard = lazy(() => import("./pages/Dashboard").then((m) => ({ default: m.Dashboard })));
const Monitor = lazy(() => import("./pages/Monitor").then((m) => ({ default: m.Monitor })));
const Quarantine = lazy(() => import("./pages/Quarantine").then((m) => ({ default: m.Quarantine })));
const SocCenter = lazy(() => import("./pages/SocCenter").then((m) => ({ default: m.SocCenter })));
const Team = lazy(() => import("./pages/Team").then((m) => ({ default: m.Team })));
const Plugins = lazy(() => import("./pages/Plugins").then((m) => ({ default: m.Plugins })));

export const APP_ROUTES: AppRoute[] = [
  { path: "/", label: "Dashboard", icon: "📊", index: true, Component: Dashboard },
  { path: "/monitor", label: "Real-Time Monitor", icon: "📡", Component: Monitor },
  { path: "/quarantine", label: "Quarantine", icon: "🗃️", Component: Quarantine },
  { path: "/soc", label: "SOC Center", icon: "🧠", Component: SocCenter },
  { path: "/team", label: "Team & Access", icon: "👥", roles: ["admin", "owner"], Component: Team },
  { path: "/plugins", label: "Plugins", icon: "🧩", roles: ["admin", "owner"], Component: Plugins },
];

/** Whether a role may see/enter a route. */
export function canAccess(route: AppRoute, role: string | undefined): boolean {
  return !route.roles || (!!role && route.roles.includes(role));
}
