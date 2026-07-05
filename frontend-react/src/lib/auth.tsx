import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, type Identity } from "./api";

interface AuthState {
  identity: Identity | null;
  loading: boolean;
  login: (u: string, p: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [loading, setLoading] = useState(true);

  // Session lives in httpOnly cookies; ask the server who we are on load.
  // If the access cookie expired, the api client transparently refreshes.
  useEffect(() => {
    api
      .me()
      .then(setIdentity)
      .catch(() => setIdentity(null))
      .finally(() => setLoading(false));
  }, []);

  async function login(username: string, password: string) {
    const res = await api.login(username, password);
    setIdentity(res.user);
  }

  async function logout() {
    try {
      await api.logout();
    } finally {
      setIdentity(null);
    }
  }

  return <AuthContext.Provider value={{ identity, loading, login, logout }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
