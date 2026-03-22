"use client";

import { useEffect, useState } from "react";
import { listAnalyses, type AnalysisJob } from "@/lib/api";
import Link from "next/link";

/* ── Analysis module descriptions for learners ─────────────── */
const MODULES = [
  {
    icon: "✉",
    label: "Email Headers",
    tech: "SPF · DKIM · DMARC",
    desc: "Verifies the sender's identity by checking authentication records. Mismatches often mean the email is spoofed.",
  },
  {
    icon: "🔗",
    label: "URL Analysis",
    tech: "Obfuscation · Redirect chains",
    desc: "Inspects every link for deceptive structure, IP addresses instead of domains, and encoding tricks used to hide destinations.",
  },
  {
    icon: "🌐",
    label: "Domain Intelligence",
    tech: "WHOIS · DNS · Typosquatting",
    desc: "Looks up when a domain was registered, who owns it, and whether it visually mimics a trusted brand like PayPal or Google.",
  },
  {
    icon: "🧠",
    label: "Language Analysis",
    tech: "NLP · Urgency · Credential bait",
    desc: "Scans email body for psychological manipulation — urgency phrases, threats, and prompts to enter passwords or bank details.",
  },
  {
    icon: "🛡",
    label: "Threat Intelligence",
    tech: "OpenPhish · PhishTank · URLhaus",
    desc: "Cross-references all URLs against real-time phishing and malware feeds maintained by the security community.",
  },
  {
    icon: "📎",
    label: "Attachment Safety",
    tech: "MIME · Macros · Double extensions",
    desc: "Detects dangerous file types, executable disguised as documents, and Office files containing malicious macros.",
  },
];

/* ── Common phishing tactics for learner education ─────────── */
const TACTICS = [
  { label: "Urgency pressure", example: '"Your account will be suspended in 24 hours"', color: "#f59e0b" },
  { label: "Impersonation", example: "paypa1.com · secure-login-microsoft.net", color: "#f43f5e" },
  { label: "Hidden redirects", example: "bit.ly/xK2p → tracks → evil.ru/steal", color: "#f97316" },
  { label: "Credential harvest", example: '"Verify your password to continue"', color: "#a78bfa" },
];

export default function Dashboard() {
  const [analyses, setAnalyses] = useState<AnalysisJob[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listAnalyses(1, 10)
      .then((data) => { setAnalyses(data.analyses); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-14">

      {/* ══ HERO ══════════════════════════════════════════════════ */}
      <section className="text-center pt-10">
        <div
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full mb-6 font-mono text-xs"
          style={{
            border: "1px solid var(--color-phismail-border)",
            color: "var(--color-phismail-text-muted)",
            background: "var(--color-phismail-surface)",
          }}
        >
          <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "#22c55e" }} />
          Analysis engine online · 9-stage forensic pipeline
        </div>

        <h1
          className="text-5xl font-bold tracking-tight mb-4 leading-tight"
          style={{ letterSpacing: "-0.02em" }}
        >
          <span style={{ color: "var(--color-phismail-purple)" }}>Spot</span>
          <span style={{ color: "var(--color-phismail-text)" }}> phishing.</span>
          <br />
          <span style={{ color: "var(--color-phismail-text-muted)", fontWeight: 400, fontSize: "0.65em" }}>
            Understand exactly why it&apos;s dangerous.
          </span>
        </h1>

        <p
          className="text-base max-w-lg mx-auto mb-10 leading-relaxed"
          style={{ color: "var(--color-phismail-text-muted)" }}
        >
          Drop a suspicious email or paste a URL. PhisMail runs it through nine
          detection modules and explains every finding in plain English — built
          for analysts who want to learn, not just get a verdict.
        </p>

        {/* CTAs */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Link
            href="/submit"
            className="btn-primary inline-flex items-center gap-2.5 justify-center"
          >
            <span style={{ fontFamily: "inherit" }}>📧</span>
            Analyze suspicious email
          </Link>
          <Link
            href="/submit"
            className="inline-flex items-center gap-2.5 justify-center px-7 py-3 rounded-lg font-semibold text-sm transition-all duration-200"
            style={{
              background: "var(--color-phismail-surface)",
              border: "1px solid var(--color-phismail-border)",
              color: "var(--color-phismail-text)",
              fontFamily: "'JetBrains Mono', monospace",
            }}
          >
            <span>🔗</span>
            Check a suspicious URL
          </Link>
        </div>
      </section>

      {/* ══ COMMON PHISHING TACTICS ═══════════════════════════════ */}
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <h2 className="text-lg font-bold" style={{ color: "var(--color-phismail-text)" }}>
            Common phishing tactics
          </h2>
          <span className="text-sm" style={{ color: "var(--color-phismail-text-muted)" }}>
            What attackers rely on
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {TACTICS.map((t) => (
            <div
              key={t.label}
              className="rounded-xl p-4"
              style={{
                background: "var(--color-phismail-surface)",
                border: `1px solid ${t.color}28`,
                borderLeft: `3px solid ${t.color}`,
              }}
            >
              <p className="font-semibold text-sm mb-1.5" style={{ color: t.color }}>
                {t.label}
              </p>
              <p
                className="text-xs leading-relaxed font-mono"
                style={{ color: "var(--color-phismail-text-muted)" }}
              >
                {t.example}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* ══ WHAT WE ANALYZE ═══════════════════════════════════════ */}
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <h2 className="text-lg font-bold" style={{ color: "var(--color-phismail-text)" }}>
            What we analyze
          </h2>
          <span className="text-sm" style={{ color: "var(--color-phismail-text-muted)" }}>
            9 detection modules, ~80 features
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {MODULES.map((m) => (
            <div key={m.label} className="module-card">
              <div className="flex items-start gap-3 mb-3">
                <span className="text-2xl leading-none">{m.icon}</span>
                <div>
                  <h3 className="font-semibold text-sm" style={{ color: "var(--color-phismail-text)" }}>
                    {m.label}
                  </h3>
                  <p
                    className="text-[11px] font-mono mt-0.5"
                    style={{ color: "var(--color-phismail-purple)" }}
                  >
                    {m.tech}
                  </p>
                </div>
              </div>
              <p className="text-sm leading-relaxed" style={{ color: "var(--color-phismail-text-muted)" }}>
                {m.desc}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* ══ RECENT ANALYSES ═══════════════════════════════════════ */}
      <section>
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-bold" style={{ color: "var(--color-phismail-text)" }}>
            Recent analyses
          </h2>
          <Link
            href="/submit"
            className="text-xs font-mono font-semibold transition-colors"
            style={{ color: "var(--color-phismail-purple)" }}
          >
            + New analysis
          </Link>
        </div>

        <div className="glass-panel-static overflow-hidden">
          {loading ? (
            <div className="p-8 space-y-3">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-12 loading-shimmer rounded" />
              ))}
            </div>
          ) : analyses.length === 0 ? (
            <div className="p-12 text-center space-y-3">
              <p className="text-3xl">🔍</p>
              <p className="font-semibold" style={{ color: "var(--color-phismail-text)" }}>
                No analyses yet
              </p>
              <p className="text-sm" style={{ color: "var(--color-phismail-text-muted)" }}>
                Submit your first suspicious email or URL to get started.
              </p>
              <Link href="/submit">
                <span className="btn-primary inline-block mt-2 text-xs px-5 py-2">
                  Start analyzing
                </span>
              </Link>
            </div>
          ) : (
            <table className="soc-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Submitted</th>
                </tr>
              </thead>
              <tbody>
                {analyses.map((a) => (
                  <tr key={a.analysis_id}>
                    <td>
                      <Link
                        href={`/analysis/${a.analysis_id}`}
                        className="font-mono text-xs hover:underline"
                        style={{ color: "var(--color-phismail-purple)" }}
                      >
                        {a.analysis_id.slice(0, 8)}…
                      </Link>
                    </td>
                    <td>
                      <span className="badge badge-low">{a.artifact_type}</span>
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          a.status === "complete"   ? "badge-low"
                          : a.status === "processing" ? "badge-medium"
                          : a.status === "failed"     ? "badge-critical"
                          : "badge-high"
                        }`}
                      >
                        {a.status}
                      </span>
                    </td>
                    <td className="font-mono text-xs" style={{ color: "var(--color-phismail-text-muted)" }}>
                      {new Date(a.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </div>
  );
}
