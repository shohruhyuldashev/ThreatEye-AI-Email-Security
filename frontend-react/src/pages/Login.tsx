import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../lib/auth";

export function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await login(username, password);
      navigate("/", { replace: true });
    } catch {
      setError("Invalid credentials.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center bg-cyber-dark">
      <form
        onSubmit={onSubmit}
        className="bg-cyber-panel border border-cyber-border rounded-xl p-8 w-full max-w-sm space-y-5"
      >
        <h1 className="text-2xl font-bold text-white text-center">
          Threat<span className="text-cyber-neon">Eye</span>
        </h1>
        <div>
          <label className="block text-xs text-gray-400 uppercase mb-1">Username</label>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full rounded-lg px-4 py-2 bg-cyber-dark border border-cyber-border text-gray-200"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 uppercase mb-1">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-lg px-4 py-2 bg-cyber-dark border border-cyber-border text-gray-200"
          />
        </div>
        {error && <p className="text-cyber-danger text-sm text-center">{error}</p>}
        <button
          type="submit"
          disabled={busy}
          className="w-full py-2.5 bg-cyber-neon text-black font-bold rounded-lg disabled:opacity-60"
        >
          {busy ? "Authenticating…" : "Sign In"}
        </button>
      </form>
    </div>
  );
}
