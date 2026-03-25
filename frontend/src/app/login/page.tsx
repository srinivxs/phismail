"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/components/AuthProvider";

export default function LoginPage() {
  const router = useRouter();
  const { login, googleLogin } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(email, password);
      router.push("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    }
    setLoading(false);
  };

  const handleGoogleLogin = async () => {
    setError("Google OAuth requires GOOGLE_CLIENT_ID to be configured. See setup instructions.");
  };

  return (
    <div className="max-w-sm mx-auto pt-16">
      <div className="text-center mb-8">
        <div
          className="w-10 h-10 rounded-lg mx-auto mb-4 flex items-center justify-center text-lg font-bold"
          style={{ background: "var(--pm-accent)", color: "#fff" }}
        >
          P
        </div>
        <h1 className="text-xl font-semibold" style={{ color: "var(--pm-text)" }}>
          Sign in to PhisMail
        </h1>
        <p className="text-sm mt-1" style={{ color: "var(--pm-text-secondary)" }}>
          Analyze phishing emails and URLs
        </p>
      </div>

      {/* Google button */}
      <button
        onClick={handleGoogleLogin}
        className="w-full flex items-center justify-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors mb-6"
        style={{
          background: "var(--pm-surface)",
          border: "1px solid var(--pm-border)",
          color: "var(--pm-text)",
        }}
      >
        <svg width="18" height="18" viewBox="0 0 24 24">
          <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/>
          <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
          <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
          <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
        </svg>
        Continue with Google
      </button>

      {/* Divider */}
      <div className="flex items-center gap-3 mb-6">
        <div className="flex-1 h-px" style={{ background: "var(--pm-border)" }} />
        <span className="text-xs" style={{ color: "var(--pm-text-muted)" }}>or</span>
        <div className="flex-1 h-px" style={{ background: "var(--pm-border)" }} />
      </div>

      {/* Email/password form */}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--pm-text-secondary)" }}>
            Email
          </label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            className="soc-input"
            required
            autoFocus
          />
        </div>
        <div>
          <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--pm-text-secondary)" }}>
            Password
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter your password"
            className="soc-input"
            required
          />
        </div>

        {error && (
          <p className="text-xs font-medium" style={{ color: "var(--pm-danger)" }}>
            {error}
          </p>
        )}

        <button type="submit" disabled={loading} className="btn-primary w-full">
          {loading ? "Signing in..." : "Sign in"}
        </button>
      </form>

      <p className="text-center text-xs mt-6" style={{ color: "var(--pm-text-secondary)" }}>
        Don&apos;t have an account?{" "}
        <Link href="/signup" style={{ color: "var(--pm-accent)" }} className="font-medium">
          Sign up
        </Link>
      </p>
    </div>
  );
}
