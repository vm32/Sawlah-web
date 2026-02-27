import { useState } from "react";
import { Shield, LogIn, UserPlus, Eye, EyeOff } from "lucide-react";

export default function Login({ onLogin }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) return;
    setError(""); setLoading(true);

    try {
      const endpoint = mode === "login" ? "/api/auth/login" : "/api/auth/register";
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || "Authentication failed");
        setLoading(false);
        return;
      }
      localStorage.setItem("sawlah_token", data.token);
      localStorage.setItem("sawlah_user", JSON.stringify({ username: data.username, role: data.role }));
      onLogin(data);
    } catch (err) {
      setError("Connection error");
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-sawlah-bg flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <Shield className="w-14 h-14 text-sawlah-red mx-auto mb-4" />
          <h1 className="text-3xl font-bold text-sawlah-text tracking-tight">Sawlah</h1>
          <p className="text-sm text-sawlah-muted mt-1">Penetration Testing Web Panel</p>
        </div>

        <div className="bg-sawlah-card border border-sawlah-border rounded-xl p-6">
          <div className="flex gap-1 p-1 bg-sawlah-surface rounded-lg mb-6">
            <button
              onClick={() => { setMode("login"); setError(""); }}
              className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-md text-sm font-semibold transition-all ${
                mode === "login" ? "bg-sawlah-red text-white shadow-lg" : "text-sawlah-dim hover:text-sawlah-muted"
              }`}
            >
              <LogIn className="w-4 h-4" /> Login
            </button>
            <button
              onClick={() => { setMode("register"); setError(""); }}
              className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-md text-sm font-semibold transition-all ${
                mode === "register" ? "bg-sawlah-red text-white shadow-lg" : "text-sawlah-dim hover:text-sawlah-muted"
              }`}
            >
              <UserPlus className="w-4 h-4" /> Register
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-sawlah-muted mb-1.5">Username</label>
              <input
                value={username} onChange={(e) => setUsername(e.target.value)}
                placeholder="admin" className="w-full" autoFocus
              />
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-sawlah-muted mb-1.5">Password</label>
              <div className="relative">
                <input
                  type={showPw ? "text" : "password"}
                  value={password} onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••" className="w-full pr-10"
                />
                <button type="button" onClick={() => setShowPw(!showPw)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-sawlah-dim hover:text-sawlah-muted">
                  {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {error && <p className="text-xs text-sawlah-red bg-red-500/10 px-3 py-2 rounded-lg">{error}</p>}

            <button
              type="submit" disabled={loading}
              className="w-full py-2.5 bg-sawlah-red text-white rounded-lg font-semibold text-sm hover:bg-sawlah-red-hover transition-colors shadow-lg shadow-sawlah-red-glow disabled:opacity-50"
            >
              {loading ? "..." : mode === "login" ? "Sign In" : "Create Account"}
            </button>
          </form>

          {mode === "login" && (
            <p className="text-[11px] text-sawlah-dim text-center mt-4">
              Default: admin / sawlah
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
