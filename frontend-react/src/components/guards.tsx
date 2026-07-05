import { Navigate, useLocation } from "react-router-dom";
import type { ReactNode } from "react";
import { useAuth } from "../lib/auth";

/** Gate a subtree behind authentication; bounces to /login preserving the target. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { identity, loading } = useAuth();
  const location = useLocation();
  if (loading) return <div className="p-8 text-gray-500">Loading…</div>;
  if (!identity) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <>{children}</>;
}

/** Gate a route by role; insufficient role redirects home rather than 403-ing. */
export function RequireRole({ roles, children }: { roles?: string[]; children: ReactNode }) {
  const { identity } = useAuth();
  if (roles && !(identity && roles.includes(identity.role))) {
    return <Navigate to="/" replace />;
  }
  return <>{children}</>;
}
