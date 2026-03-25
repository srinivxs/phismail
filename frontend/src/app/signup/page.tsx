"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/components/AuthProvider";

export default function SignupPage() {
  const router = useRouter();
  const { signup } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await signup(email, password, displayName || undefined);
      router.push("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Signup failed");
    }
    setLoading(false);
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
          Create your account
        </h1>
        <p className="text-sm mt-1" style={{ color: "var(--pm-text-secondary)" }}>
          Start analyzing phishing emails and URLs
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--pm-text-secondary)" }}>
            Display name <span style={{ color: "var(--pm-text-muted)" }}>(optional)</span>
          </label>
          <input
            type="text"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="Your name"
            className="soc-input"
            maxLength={100}
          />
        </div>
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
            placeholder="Min 8 chars, uppercase, lowercase, digit"
            className="soc-input"
            required
            minLength={8}
          />
          <p className="text-[11px] mt-1" style={{ color: "var(--pm-text-muted)" }}>
            At least 8 characters with uppercase, lowercase, and a number
          </p>
        </div>

        {error && (
          <p className="text-xs font-medium" style={{ color: "var(--pm-danger)" }}>
            {error}
          </p>
        )}

        <button type="submit" disabled={loading} className="btn-primary w-full">
          {loading ? "Creating account..." : "Create account"}
        </button>
      </form>

      <p className="text-center text-xs mt-6" style={{ color: "var(--pm-text-secondary)" }}>
        Already have an account?{" "}
        <Link href="/login" style={{ color: "var(--pm-accent)" }} className="font-medium">
          Sign in
        </Link>
      </p>
    </div>
  );
}
