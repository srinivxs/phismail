"use client";

import { useEffect, useState } from "react";
import { listAnalyses, type AnalysisJob } from "@/lib/api";
import Link from "next/link";

const STATUS_MAP: Record<string, { label: string; color: string }> = {
  complete:   { label: "Complete",   color: "var(--pm-success)" },
  processing: { label: "Running",    color: "var(--pm-warning)" },
  failed:     { label: "Failed",     color: "var(--pm-danger)" },
  pending:    { label: "Queued",     color: "var(--pm-text-muted)" },
};

function timeAgo(dateStr: string): string {
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

/* Small reusable icon components */
function MailIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="4" width="20" height="16" rx="2" /><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
    </svg>
  );
}

function LinkIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
    </svg>
  );
}

function ArrowRightIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="5" y1="12" x2="19" y2="12" /><polyline points="12 5 19 12 12 19" />
    </svg>
  );
}

function ChevronRightIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
      <polyline points="9 18 15 12 9 6" />
    </svg>
  );
}

function ShieldIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

function SearchIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
      <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  );
}

export default function Dashboard() {
  const [analyses, setAnalyses] = useState<AnalysisJob[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listAnalyses(1, 10)
      .then((data) => { setAnalyses(data.analyses); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const stats = {
    total: analyses.length,
    complete: analyses.filter((a) => a.status === "complete").length,
    processing: analyses.filter((a) => a.status === "processing").length,
  };

  return (
    <div className="space-y-10 pb-8">

      {/* ── HERO ── */}
      <section className="pt-10 pb-4">
        <div className="max-w-2xl">
          <h1
            className="text-3xl sm:text-4xl font-semibold tracking-tight leading-tight mb-3"
            style={{ color: "var(--pm-text)", letterSpacing: "-0.02em" }}
          >
            Phishing analysis<br />
            <span style={{ color: "var(--pm-accent)" }}>you can understand.</span>
          </h1>

          <p
            className="text-base leading-relaxed mb-8 max-w-lg"
            style={{ color: "var(--pm-text-secondary)" }}
          >
            9-stage forensic pipeline. Every signal explained in plain English.
            Drop an email or paste a URL to start.
          </p>

          <div className="flex flex-wrap gap-3">
            <Link href="/submit" className="btn-primary inline-flex items-center gap-2 text-sm">
              Start analysis
              <ArrowRightIcon />
            </Link>
            <a href="https://github.com/srinivxs/phismail" target="_blank" rel="noopener noreferrer" className="btn-secondary inline-flex items-center gap-2 text-sm">
              View source
            </a>
          </div>
        </div>
      </section>

      {/* ── STATS ── */}
      <section className="grid grid-cols-3 gap-4">
        {[
          { label: "Total scans", value: stats.total, color: "var(--pm-accent)" },
          { label: "Completed", value: stats.complete, color: "var(--pm-success)" },
          { label: "In progress", value: stats.processing, color: "var(--pm-warning)" },
        ].map((s) => (
          <div
            key={s.label}
            className="card rounded-xl p-5"
          >
            <p className="text-xs font-medium mb-2" style={{ color: "var(--pm-text-secondary)" }}>
              {s.label}
            </p>
            <p className="text-2xl font-semibold font-mono" style={{ color: s.color }}>
              {loading ? "-" : s.value}
            </p>
          </div>
        ))}
      </section>

      {/* ── HOW IT WORKS (replaces pipeline viz) ── */}
      <section>
        <h2 className="text-sm font-medium mb-4" style={{ color: "var(--pm-text-secondary)" }}>
          How it works
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {[
            {
              icon: <MailIcon />,
              title: "Submit",
              desc: "Upload an .eml file or paste a suspicious URL",
            },
            {
              icon: <ShieldIcon />,
              title: "Analyze",
              desc: "9 engines check headers, URLs, domains, NLP, and threat feeds",
            },
            {
              icon: <SearchIcon />,
              title: "Understand",
              desc: "Get a plain-English verdict with risk breakdown and actionable advice",
            },
          ].map((step, i) => (
            <div key={i} className="card rounded-xl p-5 flex gap-4">
              <div
                className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
                style={{
                  background: "var(--pm-accent-muted)",
                  color: "var(--pm-accent)",
                }}
              >
                {step.icon}
              </div>
              <div>
                <p className="text-sm font-medium mb-1" style={{ color: "var(--pm-text)" }}>
                  {step.title}
                </p>
                <p className="text-xs leading-relaxed" style={{ color: "var(--pm-text-secondary)" }}>
                  {step.desc}
                </p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── RECENT SCANS ── */}
      <section>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-medium" style={{ color: "var(--pm-text-secondary)" }}>
            Recent scans
          </h2>
          <Link
            href="/submit"
            className="btn-secondary text-xs px-3 py-1.5 inline-flex items-center gap-1.5"
          >
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round">
              <line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" />
            </svg>
            New scan
          </Link>
        </div>

        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-14 loading-shimmer rounded-xl" />
            ))}
          </div>
        ) : analyses.length === 0 ? (
          <div
            className="card rounded-xl p-16 text-center"
            style={{ border: "1px dashed var(--pm-border)" }}
          >
            <div
              className="w-10 h-10 rounded-full mx-auto mb-4 flex items-center justify-center"
              style={{ background: "var(--pm-accent-muted)", color: "var(--pm-accent)" }}
            >
              <SearchIcon />
            </div>
            <p className="font-medium text-sm mb-1" style={{ color: "var(--pm-text)" }}>
              No scans yet
            </p>
            <p className="text-xs mb-5" style={{ color: "var(--pm-text-secondary)" }}>
              Submit a suspicious email or URL to get started
            </p>
            <Link href="/submit" className="btn-primary text-xs px-5 py-2.5 inline-block">
              Start first scan
            </Link>
          </div>
        ) : (
          <div className="space-y-1">
            {analyses.map((a) => {
              const st = STATUS_MAP[a.status] || STATUS_MAP.pending;
              return (
                <Link
                  key={a.analysis_id}
                  href={`/analysis/${a.analysis_id}`}
                  className="flex items-center gap-4 px-4 py-3 rounded-lg transition-colors duration-100"
                  style={{ background: "transparent" }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--pm-surface)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  {/* Type icon */}
                  <div
                    className="w-8 h-8 rounded-md flex items-center justify-center shrink-0"
                    style={{
                      background: "var(--pm-surface)",
                      border: "1px solid var(--pm-border)",
                      color: "var(--pm-text-secondary)",
                    }}
                  >
                    {a.artifact_type === "email" ? <MailIcon /> : <LinkIcon />}
                  </div>

                  {/* ID + type */}
                  <div className="flex-1 min-w-0">
                    <p className="font-mono text-xs font-medium truncate" style={{ color: "var(--pm-text)" }}>
                      {a.analysis_id.slice(0, 12)}...
                    </p>
                    <p className="text-[11px] mt-0.5" style={{ color: "var(--pm-text-muted)" }}>
                      {a.artifact_type}
                    </p>
                  </div>

                  {/* Status */}
                  <div className="flex items-center gap-1.5 shrink-0">
                    <span
                      className="w-1.5 h-1.5 rounded-full"
                      style={{ background: st.color }}
                    />
                    <span className="text-xs" style={{ color: "var(--pm-text-secondary)" }}>
                      {st.label}
                    </span>
                  </div>

                  {/* Time */}
                  <p className="text-xs shrink-0 hidden sm:block" style={{ color: "var(--pm-text-muted)" }}>
                    {timeAgo(a.created_at)}
                  </p>

                  {/* Arrow */}
                  <span style={{ color: "var(--pm-text-muted)" }}>
                    <ChevronRightIcon />
                  </span>
                </Link>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
