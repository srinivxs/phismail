"use client";

import { useEffect, useState } from "react";
import { listAnalyses, type AnalysisJob } from "@/lib/api";
import Link from "next/link";
import PipelineView from "@/components/PipelineView";

export default function Dashboard() {
  const [analyses, setAnalyses] = useState<AnalysisJob[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listAnalyses(1, 10).then((data) => {
      setAnalyses(data.analyses);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-10">

      {/* ── Hero ── */}
      <section className="text-center pt-10 pb-2">
        <div className="inline-flex items-center gap-2 text-xs font-mono px-3 py-1 rounded mb-5"
          style={{ border: "1px solid var(--color-phismail-border)", color: "var(--color-phismail-text-muted)", background: "var(--color-phismail-surface)" }}
        >
          <span style={{ color: "var(--color-phismail-green)" }}>●</span>
          SOC Platform v0.1 — Active
        </div>

        <h1 className="text-4xl font-bold tracking-tight mb-4">
          <span style={{ color: "var(--color-phismail-purple)" }}>&lt;</span>
          <span style={{ color: "var(--color-phismail-text)" }}> Phishing Investigation </span>
          <span style={{ color: "var(--color-phismail-green)" }}>/&gt;</span>
        </h1>

        <p className="font-mono text-sm max-w-xl mx-auto" style={{ color: "var(--color-phismail-text-muted)" }}>
          // SOC-grade analysis engine · deep threat intelligence · 9-stage forensic pipeline
        </p>
      </section>

      {/* ── Quick Actions ── */}
      <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Link href="/submit" className="glass-panel p-7 group cursor-pointer block">
          <div className="flex items-start gap-4">
            <div
              className="w-10 h-10 rounded flex items-center justify-center shrink-0 font-mono text-xs font-bold transition-all duration-300 group-hover:scale-110"
              style={{
                background: "var(--color-phismail-purple-glow)",
                border:     "1px solid var(--color-phismail-border)",
                color:      "var(--color-phismail-purple)",
              }}
            >
              &lt;/&gt;
            </div>
            <div className="min-w-0">
              <h3 className="font-mono font-semibold text-sm mb-1" style={{ color: "var(--color-phismail-text)" }}>
                upload_email<span style={{ color: "var(--color-phismail-green)" }}>()</span>
              </h3>
              <p className="text-xs font-mono" style={{ color: "var(--color-phismail-text-muted)" }}>
                // Drop .eml file for full forensic analysis
              </p>
            </div>
          </div>
        </Link>

        <Link href="/submit" className="glass-panel p-7 group cursor-pointer block">
          <div className="flex items-start gap-4">
            <div
              className="w-10 h-10 rounded flex items-center justify-center shrink-0 font-mono text-xs font-bold transition-all duration-300 group-hover:scale-110"
              style={{
                background: "var(--color-phismail-purple-glow)",
                border:     "1px solid var(--color-phismail-border)",
                color:      "var(--color-phismail-purple)",
              }}
            >
              URL
            </div>
            <div className="min-w-0">
              <h3 className="font-mono font-semibold text-sm mb-1" style={{ color: "var(--color-phismail-text)" }}>
                analyze_url<span style={{ color: "var(--color-phismail-green)" }}>()</span>
              </h3>
              <p className="text-xs font-mono" style={{ color: "var(--color-phismail-text-muted)" }}>
                // Paste suspicious link for deep threat intelligence
              </p>
            </div>
          </div>
        </Link>
      </section>

      {/* ── Pipeline Architecture ── */}
      <PipelineView />

      {/* ── Recent Analyses ── */}
      <section>
        <div className="flex items-center gap-3 mb-4">
          <span className="font-mono text-sm font-bold" style={{ color: "var(--color-phismail-purple)" }}>&lt;</span>
          <h2 className="font-mono text-sm font-bold" style={{ color: "var(--color-phismail-text)" }}>recent_analyses</h2>
          <span className="font-mono text-sm font-bold" style={{ color: "var(--color-phismail-green)" }}>/&gt;</span>
        </div>

        <div className="glass-panel-static overflow-hidden">
          {loading ? (
            <div className="p-8 space-y-3">
              {[1,2,3].map(i => (
                <div key={i} className="h-12 loading-shimmer rounded" />
              ))}
            </div>
          ) : analyses.length === 0 ? (
            <div className="p-12 text-center">
              <p className="font-mono text-sm mb-1" style={{ color: "var(--color-phismail-text-muted)" }}>
                $ <span style={{ color: "var(--color-phismail-green)" }}>no analyses found</span>
              </p>
              <p className="font-mono text-xs" style={{ color: "var(--color-phismail-text-dim)" }}>
                // submit an email or URL to get started
              </p>
            </div>
          ) : (
            <table className="soc-table">
              <thead>
                <tr>
                  <th>analysis_id</th>
                  <th>type</th>
                  <th>status</th>
                  <th>submitted</th>
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
                      <span className={`badge ${
                        a.status === 'complete'   ? 'badge-low'      :
                        a.status === 'processing' ? 'badge-medium'   :
                        a.status === 'failed'     ? 'badge-critical' : 'badge-high'
                      }`}>
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
