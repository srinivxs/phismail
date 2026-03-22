"use client";

import { useState, useCallback } from "react";
import { submitUrl, submitEmail } from "@/lib/api";
import { useRouter } from "next/navigation";

/* ── Learning tips shown alongside the form ─────────────────── */
const EMAIL_TIPS = [
  {
    icon: "📬",
    title: "How to export .eml",
    body: "In Gmail: open email → ⋮ menu → \"Download message\". In Outlook: File → Save As → .msg (then rename to .eml).",
  },
  {
    icon: "🕵",
    title: "What to look for first",
    body: "Check the From address carefully. Does the display name match the actual email address? Is the domain slightly misspelled?",
  },
  {
    icon: "⚠",
    title: "Red flag phrases",
    body: "\"Urgent action required\", \"verify your account\", \"your payment failed\" — these create artificial panic to bypass your critical thinking.",
  },
];

const URL_TIPS = [
  {
    icon: "🔍",
    title: "What makes a URL suspicious",
    body: "Look for IP addresses instead of domain names, excessive subdomains, or domains that resemble brands (paypa1.com, gooogle.net).",
  },
  {
    icon: "🔗",
    title: "About redirect chains",
    body: "Attackers use URL shorteners and redirects to hide the true destination. PhisMail follows every hop to the final URL.",
  },
  {
    icon: "🛡",
    title: "Safe to analyze",
    body: "You're only submitting the URL string — we never open it in your browser. The backend safely traces redirects in isolation.",
  },
];

export default function SubmitPage() {
  const router = useRouter();
  const [tab, setTab] = useState<"url" | "email">("email");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [isDragOver, setIsDragOver] = useState(false);

  const handleUrlSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setError("");
    try {
      let normalized = url.trim();
      if (!/^https?:\/\//i.test(normalized)) normalized = "https://" + normalized;
      const job = await submitUrl(normalized);
      router.push(`/analysis/${job.analysis_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to submit URL");
    }
    setLoading(false);
  };

  const handleEmailSubmit = async () => {
    if (!file) return;
    setLoading(true);
    setError("");
    try {
      const job = await submitEmail(file);
      router.push(`/analysis/${job.analysis_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to upload email");
    }
    setLoading(false);
  };

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped && dropped.name.toLowerCase().endsWith(".eml")) {
      setFile(dropped);
      setError("");
    } else {
      setError("Only .eml files are accepted");
    }
  }, []);

  const tips = tab === "email" ? EMAIL_TIPS : URL_TIPS;

  return (
    <div className="max-w-5xl mx-auto pt-8">

      {/* ── Header ── */}
      <div className="mb-8">
        <h1
          className="text-3xl font-bold tracking-tight mb-2"
          style={{ color: "var(--color-phismail-text)", letterSpacing: "-0.01em" }}
        >
          Analyze a suspicious{" "}
          <span style={{ color: "var(--color-phismail-purple)" }}>
            {tab === "email" ? "email" : "URL"}
          </span>
        </h1>
        <p className="text-sm" style={{ color: "var(--color-phismail-text-muted)" }}>
          {tab === "email"
            ? "Upload an .eml file for full forensic header, link, and attachment analysis."
            : "Paste any URL to trace redirect chains, check threat feeds, and analyze domain reputation."}
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">

        {/* ── LEFT: Form ── */}
        <div className="lg:col-span-3 space-y-5">

          {/* Tab switcher */}
          <div
            className="flex gap-1 p-1 w-fit rounded-lg"
            style={{
              background: "var(--color-phismail-surface)",
              border: "1px solid var(--color-phismail-border)",
            }}
          >
            {(["email", "url"] as const).map((t) => (
              <button
                key={t}
                onClick={() => { setTab(t); setError(""); }}
                className="px-5 py-2 rounded-md text-sm font-semibold transition-all duration-200"
                style={{
                  background:
                    tab === t ? "var(--color-phismail-purple)" : "transparent",
                  color:
                    tab === t ? "#000000" : "var(--color-phismail-text-muted)",
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: "0.8rem",
                }}
              >
                {t === "email" ? "📧 .eml file" : "🔗 URL"}
              </button>
            ))}
          </div>

          {/* URL form */}
          {tab === "url" && (
            <form onSubmit={handleUrlSubmit} className="glass-panel p-7 space-y-5">
              <div>
                <label
                  className="block text-xs font-semibold uppercase tracking-widest mb-2 font-mono"
                  style={{ color: "var(--color-phismail-text-muted)" }}
                >
                  Suspicious URL
                </label>
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://suspicious-site.example.com/login"
                  className="soc-input"
                  autoFocus
                />
                <p
                  className="mt-2 text-xs"
                  style={{ color: "var(--color-phismail-text-muted)" }}
                >
                  https:// will be added automatically if omitted
                </p>
              </div>
              <button
                type="submit"
                disabled={loading || !url.trim()}
                className="btn-primary w-full"
              >
                {loading ? "Analyzing…" : "Run analysis"}
              </button>
            </form>
          )}

          {/* Email form */}
          {tab === "email" && (
            <div className="glass-panel p-7 space-y-5">
              <div
                className={`drop-zone ${isDragOver ? "active" : ""}`}
                onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
                onDragLeave={() => setIsDragOver(false)}
                onDrop={onDrop}
                onClick={() => document.getElementById("file-input")?.click()}
              >
                {file ? (
                  <div className="space-y-2">
                    <p
                      className="text-2xl font-bold"
                      style={{ color: "#22c55e" }}
                    >
                      ✓
                    </p>
                    <p
                      className="font-mono text-sm font-bold"
                      style={{ color: "var(--color-phismail-text)" }}
                    >
                      {file.name}
                    </p>
                    <p
                      className="text-xs"
                      style={{ color: "var(--color-phismail-text-muted)" }}
                    >
                      {(file.size / 1024).toFixed(1)} KB, ready to analyze
                    </p>
                    <button
                      className="text-xs underline mt-1"
                      style={{ color: "var(--color-phismail-text-muted)" }}
                      onClick={(e) => { e.stopPropagation(); setFile(null); }}
                    >
                      Remove file
                    </button>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <p className="text-3xl">📂</p>
                    <p
                      className="font-semibold"
                      style={{ color: "var(--color-phismail-text)" }}
                    >
                      Drop your .eml file here
                    </p>
                    <p
                      className="text-sm"
                      style={{ color: "var(--color-phismail-text-muted)" }}
                    >
                      or{" "}
                      <span style={{ color: "var(--color-phismail-purple)" }}>
                        click to browse
                      </span>{" "}
                      · max 5 MB
                    </p>
                  </div>
                )}
              </div>
              <input
                id="file-input"
                type="file"
                accept=".eml"
                onChange={(e) => { setFile(e.target.files?.[0] || null); setError(""); }}
                className="hidden"
              />
              <button
                onClick={handleEmailSubmit}
                disabled={loading || !file}
                className="btn-primary w-full"
              >
                {loading ? "Uploading & analyzing…" : "Run analysis"}
              </button>
            </div>
          )}

          {/* Error */}
          {error && (
            <div
              className="rounded-lg p-4"
              style={{
                background: "rgba(244,63,94,0.07)",
                border: "1px solid rgba(244,63,94,0.30)",
              }}
            >
              <p
                className="text-sm font-semibold"
                style={{ color: "var(--color-severity-critical)" }}
              >
                {error}
              </p>
            </div>
          )}
        </div>

        {/* ── RIGHT: Educational tips ── */}
        <div className="lg:col-span-2 space-y-4">
          <h3
            className="text-xs font-mono font-bold uppercase tracking-widest"
            style={{ color: "var(--color-phismail-text-muted)" }}
          >
            Learner notes
          </h3>

          {tips.map((tip) => (
            <div
              key={tip.title}
              className="rounded-xl p-4 space-y-2"
              style={{
                background: "var(--color-phismail-surface)",
                border: "1px solid var(--color-phismail-border)",
              }}
            >
              <div className="flex items-center gap-2">
                <span className="text-lg">{tip.icon}</span>
                <p
                  className="font-semibold text-sm"
                  style={{ color: "var(--color-phismail-text)" }}
                >
                  {tip.title}
                </p>
              </div>
              <p
                className="text-sm leading-relaxed"
                style={{ color: "var(--color-phismail-text-muted)" }}
              >
                {tip.body}
              </p>
            </div>
          ))}

          <div className="edu-callout">
            <p className="text-xs font-mono font-bold uppercase tracking-wider mb-2" style={{ color: "var(--color-phismail-green)" }}>
              Privacy note
            </p>
            Uploaded emails are analyzed in memory and not stored permanently. Only extracted metadata and indicators are retained.
          </div>
        </div>

      </div>
    </div>
  );
}
