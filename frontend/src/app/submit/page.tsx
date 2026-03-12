"use client";

import { useState, useCallback } from "react";
import { submitUrl, submitEmail } from "@/lib/api";
import { useRouter } from "next/navigation";

export default function SubmitPage() {
  const router = useRouter();
  const [tab, setTab] = useState<"url" | "email">("url");
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
      if (!/^https?:\/\//i.test(normalized)) {
        normalized = "https://" + normalized;
      }
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
    } else {
      setError("Only .eml files are accepted");
    }
  }, []);

  return (
    <div className="max-w-2xl mx-auto space-y-8 pt-8">

      {/* ── Header ── */}
      <div className="text-center">
        <h1 className="text-3xl font-bold tracking-tight mb-3">
          <span style={{ color: "var(--color-phismail-purple)" }}>&lt;</span>
          <span style={{ color: "var(--color-phismail-text)" }}> Submit Artifact </span>
          <span style={{ color: "var(--color-phismail-green)" }}>/&gt;</span>
        </h1>
        <p className="font-mono text-xs" style={{ color: "var(--color-phismail-text-muted)" }}>
          // upload suspicious email or paste URL for deep analysis
        </p>
      </div>

      {/* ── Tab Switcher ── */}
      <div
        className="flex gap-1 p-1 mx-auto w-fit rounded"
        style={{ background: "var(--color-phismail-surface)", border: "1px solid var(--color-phismail-border)" }}
      >
        {(["url", "email"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className="px-5 py-2 rounded text-xs font-mono font-semibold transition-all duration-200"
            style={{
              background: tab === t ? "var(--color-phismail-purple)"   : "transparent",
              color:      tab === t ? "#ffffff"                          : "var(--color-phismail-text-muted)",
              border:     tab === t ? "1px solid rgba(0,112,243,0.6)"   : "1px solid transparent",
              boxShadow:  tab === t ? "0 0 10px rgba(0,112,243,0.3)"    : "none",
            }}
          >
            {t === "url" ? "[ URL ]" : "[ .eml ]"}
          </button>
        ))}
      </div>

      {/* ── URL Tab ── */}
      {tab === "url" && (
        <form onSubmit={handleUrlSubmit} className="glass-panel p-8 space-y-6">
          <div>
            <label className="block text-xs font-mono font-semibold mb-2 uppercase tracking-widest"
              style={{ color: "var(--color-phismail-text-muted)" }}
            >
              // target URL
            </label>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://suspicious-site.example.com/login"
              className="soc-input"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !url.trim()}
            className="btn-primary w-full"
          >
            {loading ? "[ ANALYZING... ]" : "[ ANALYZE URL ]"}
          </button>
        </form>
      )}

      {/* ── Email Tab ── */}
      {tab === "email" && (
        <div className="glass-panel p-8 space-y-6">
          <div
            className={`drop-zone ${isDragOver ? "active" : ""}`}
            onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
            onDragLeave={() => setIsDragOver(false)}
            onDrop={onDrop}
            onClick={() => document.getElementById("file-input")?.click()}
          >
            {file ? (
              <div className="space-y-2">
                <p className="font-mono text-sm font-bold" style={{ color: "var(--color-phismail-green)" }}>
                  ✓ {file.name}
                </p>
                <p className="font-mono text-xs" style={{ color: "var(--color-phismail-text-muted)" }}>
                  {(file.size / 1024).toFixed(1)} KB — ready to analyze
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                <p className="font-mono text-base font-bold" style={{ color: "var(--color-phismail-purple)" }}>
                  DROP .eml FILE
                </p>
                <p className="font-mono text-xs" style={{ color: "var(--color-phismail-text-muted)" }}>
                  // drag & drop or click to browse · max 5MB
                </p>
              </div>
            )}
          </div>
          <input
            id="file-input"
            type="file"
            accept=".eml"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
            className="hidden"
          />
          <button
            onClick={handleEmailSubmit}
            disabled={loading || !file}
            className="btn-primary w-full"
          >
            {loading ? "[ UPLOADING... ]" : "[ ANALYZE EMAIL ]"}
          </button>
        </div>
      )}

      {/* ── Error ── */}
      {error && (
        <div
          className="rounded p-4"
          style={{ background: "rgba(248,81,73,0.08)", border: "1px solid rgba(248,81,73,0.3)" }}
        >
          <p className="font-mono text-xs" style={{ color: "var(--color-severity-critical)" }}>
            ERROR: {error}
          </p>
        </div>
      )}
    </div>
  );
}
