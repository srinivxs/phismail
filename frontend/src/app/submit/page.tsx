"use client";

import { useState, useCallback } from "react";
import { submitUrl, submitEmail } from "@/lib/api";
import { useRouter } from "next/navigation";

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

  return (
    <div className="max-w-2xl mx-auto pt-8">

      {/* Header */}
      <div className="mb-8">
        <h1
          className="text-2xl font-semibold tracking-tight mb-2"
          style={{ color: "var(--pm-text)", letterSpacing: "-0.01em" }}
        >
          Analyze a suspicious {tab === "email" ? "email" : "URL"}
        </h1>
        <p className="text-sm" style={{ color: "var(--pm-text-secondary)" }}>
          {tab === "email"
            ? "Upload an .eml file for full forensic header, link, and attachment analysis."
            : "Paste any URL to trace redirect chains, check threat feeds, and analyze domain reputation."}
        </p>
      </div>

      {/* Tab switcher */}
      <div
        className="flex gap-1 p-1 w-fit rounded-lg mb-6"
        style={{
          background: "var(--pm-surface)",
          border: "1px solid var(--pm-border)",
        }}
      >
        {(["email", "url"] as const).map((t) => (
          <button
            key={t}
            onClick={() => { setTab(t); setError(""); }}
            className="px-4 py-2 rounded-md text-sm font-medium transition-all duration-150"
            style={{
              background: tab === t ? "var(--pm-accent)" : "transparent",
              color: tab === t ? "#ffffff" : "var(--pm-text-secondary)",
            }}
          >
            {t === "email" ? "Email (.eml)" : "URL"}
          </button>
        ))}
      </div>

      {/* URL form */}
      {tab === "url" && (
        <form onSubmit={handleUrlSubmit} className="card rounded-xl p-6 space-y-5">
          <div>
            <label
              className="block text-xs font-medium mb-2"
              style={{ color: "var(--pm-text-secondary)" }}
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
            <p className="mt-2 text-xs" style={{ color: "var(--pm-text-muted)" }}>
              https:// is added automatically if omitted
            </p>
          </div>
          <button type="submit" disabled={loading || !url.trim()} className="btn-primary w-full">
            {loading ? "Analyzing..." : "Run analysis"}
          </button>
        </form>
      )}

      {/* Email form */}
      {tab === "email" && (
        <div className="card rounded-xl p-6 space-y-5">
          <div
            className={`drop-zone ${isDragOver ? "active" : ""}`}
            onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
            onDragLeave={() => setIsDragOver(false)}
            onDrop={onDrop}
            onClick={() => document.getElementById("file-input")?.click()}
          >
            {file ? (
              <div className="space-y-2">
                <div
                  className="w-10 h-10 rounded-full mx-auto flex items-center justify-center"
                  style={{ background: "rgba(34, 197, 94, 0.10)", color: "var(--pm-success)" }}
                >
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                </div>
                <p className="font-mono text-sm font-medium" style={{ color: "var(--pm-text)" }}>
                  {file.name}
                </p>
                <p className="text-xs" style={{ color: "var(--pm-text-secondary)" }}>
                  {(file.size / 1024).toFixed(1)} KB
                </p>
                <button
                  className="text-xs transition-colors"
                  style={{ color: "var(--pm-text-muted)" }}
                  onMouseEnter={(e) => (e.currentTarget.style.color = "var(--pm-danger)")}
                  onMouseLeave={(e) => (e.currentTarget.style.color = "var(--pm-text-muted)")}
                  onClick={(e) => { e.stopPropagation(); setFile(null); }}
                >
                  Remove file
                </button>
              </div>
            ) : (
              <div className="space-y-3">
                <div
                  className="w-10 h-10 rounded-full mx-auto flex items-center justify-center"
                  style={{ background: "var(--pm-accent-muted)", color: "var(--pm-accent)" }}
                >
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="17 8 12 3 7 8" /><line x1="12" y1="3" x2="12" y2="15" />
                  </svg>
                </div>
                <p className="font-medium text-sm" style={{ color: "var(--pm-text)" }}>
                  Drop your .eml file here
                </p>
                <p className="text-xs" style={{ color: "var(--pm-text-secondary)" }}>
                  or <span style={{ color: "var(--pm-accent)" }}>click to browse</span> &middot; max 5 MB
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
            {loading ? "Uploading & analyzing..." : "Run analysis"}
          </button>
        </div>
      )}

      {/* Error */}
      {error && (
        <div
          className="rounded-lg p-4 mt-4"
          style={{
            background: "rgba(239, 68, 68, 0.06)",
            border: "1px solid rgba(239, 68, 68, 0.20)",
          }}
        >
          <p className="text-sm font-medium" style={{ color: "var(--pm-danger)" }}>
            {error}
          </p>
        </div>
      )}

      {/* Privacy note */}
      <div className="edu-callout mt-6">
        <p className="text-xs font-medium mb-1" style={{ color: "var(--pm-accent)" }}>
          Privacy
        </p>
        <p className="text-xs leading-relaxed">
          Uploaded emails are analyzed in memory and not stored permanently. Only extracted metadata and indicators are retained.
        </p>
      </div>
    </div>
  );
}
