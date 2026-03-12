"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { getAnalysisStatus, getReport, type AnalysisJob, type InvestigationReport } from "@/lib/api";
import {
  VerdictBadge,
  RiskGauge,
  IndicatorList,
  ExplainabilityChart,
  RedirectChainView,
  DomainIntelCard,
  AnalysisTimeline,
} from "@/components";

/* ─── Verdict colour palette ───────────────────────────── */
const VERDICT_PALETTE = {
  PHISHING:   { bg: "rgba(248,81,73,0.07)",   border: "rgba(248,81,73,0.28)",   accent: "#f85149" },
  SUSPICIOUS: { bg: "rgba(227,179,65,0.07)",  border: "rgba(227,179,65,0.26)",  accent: "#e3b341" },
  MARKETING:  { bg: "rgba(167,139,250,0.07)", border: "rgba(167,139,250,0.26)", accent: "#a78bfa" },
  SAFE:       { bg: "rgba(63,185,80,0.07)",   border: "rgba(63,185,80,0.26)",   accent: "#3fb950" },
} as const;

/* ─── Stat card ────────────────────────────────────────── */
function StatCard({ label, value, sub, accent }: { label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <div
      className="rounded p-5 transition-all duration-200"
      style={{
        background:    "var(--color-phismail-panel)",
        border:        "1px solid var(--color-phismail-border)",
        backdropFilter: "blur(16px)",
      }}
    >
      <p className="text-[10px] font-mono font-bold uppercase tracking-widest mb-2"
        style={{ color: "var(--color-phismail-text-muted)" }}
      >
        // {label}
      </p>
      <p className="text-2xl font-bold font-mono" style={{ color: accent || "var(--color-phismail-text)" }}>
        {value}
      </p>
      {sub && (
        <p className="text-[11px] font-mono mt-1" style={{ color: "var(--color-phismail-text-muted)" }}>
          {sub}
        </p>
      )}
    </div>
  );
}

/* ─── Section header ───────────────────────────────────── */
function SectionHeader({ title, count }: { title: string; count?: number }) {
  return (
    <div className="flex items-center gap-2 mb-4">
      <span className="font-mono text-sm font-bold" style={{ color: "var(--color-phismail-purple)" }}>&lt;</span>
      <h2 className="font-mono text-sm font-bold" style={{ color: "var(--color-phismail-text)" }}>{title}</h2>
      <span className="font-mono text-sm font-bold" style={{ color: "var(--color-phismail-green)" }}>/&gt;</span>
      {count !== undefined && (
        <span
          className="text-[10px] px-2 py-0.5 rounded font-mono font-bold"
          style={{ background: "var(--color-phismail-purple-glow)", color: "var(--color-phismail-purple)" }}
        >
          {count}
        </span>
      )}
    </div>
  );
}

/* ─── Main page ────────────────────────────────────────── */
export default function AnalysisPage() {
  const params = useParams();
  const id = params.id as string;
  const [status, setStatus] = useState<AnalysisJob | null>(null);
  const [report, setReport] = useState<InvestigationReport | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!id) return;
    const pollStatus = async () => {
      try {
        const s = await getAnalysisStatus(id);
        setStatus(s);
        if (s.status === "complete") {
          const r = await getReport(id);
          setReport(r);
        } else if (s.status !== "failed") {
          setTimeout(pollStatus, 3000);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to fetch analysis");
      }
    };
    pollStatus();
  }, [id]);

  /* ── Error ── */
  if (error) {
    return (
      <div className="max-w-2xl mx-auto mt-10">
        <div
          className="rounded p-8 text-center"
          style={{ background: "rgba(248,81,73,0.07)", border: "1px solid rgba(248,81,73,0.28)", backdropFilter: "blur(16px)" }}
        >
          <p className="font-mono text-sm font-bold" style={{ color: "var(--color-severity-critical)" }}>
            ERROR: {error}
          </p>
        </div>
      </div>
    );
  }

  /* ── Initial skeleton ── */
  if (!status) {
    return (
      <div className="space-y-4 pt-8">
        <div className="h-36 loading-shimmer rounded" />
        <div className="h-20 loading-shimmer rounded" />
        <div className="h-64 loading-shimmer rounded" />
      </div>
    );
  }

  /* ── Processing / Pending ── */
  if (status.status === "pending" || status.status === "processing") {
    return (
      <div className="max-w-3xl mx-auto pt-10">
        <AnalysisTimeline
          status={status.status}
          analysisId={id}
          artifactType={status.artifact_type}
        />
      </div>
    );
  }

  /* ── Failed ── */
  if (status.status === "failed") {
    return (
      <div className="max-w-3xl mx-auto pt-10">
        <AnalysisTimeline
          status="failed"
          analysisId={id}
          artifactType={status.artifact_type}
        />
      </div>
    );
  }

  /* ── No report yet ── */
  if (!report) {
    return <div className="h-64 loading-shimmer rounded mt-8" />;
  }

  const palette = VERDICT_PALETTE[report.verdict] ?? VERDICT_PALETTE.SAFE;
  const submittedAt = report.created_at ? new Date(report.created_at).toLocaleString() : "—";

  return (
    <div className="space-y-6 pt-8">

      {/* ═══════════════════════════════════════════
          INVESTIGATION HEADER
      ═══════════════════════════════════════════ */}
      <section
        className="rounded p-6 md:p-8 overflow-hidden"
        style={{
          background:    palette.bg,
          border:        `1px solid ${palette.border}`,
          backdropFilter: "blur(16px)",
        }}
      >
        {/* Top meta row */}
        <div className="flex flex-wrap items-center justify-between gap-3 mb-6">
          <div className="flex items-center gap-3 min-w-0">
            <span
              className="text-[10px] font-mono font-bold uppercase tracking-widest px-2 py-1 rounded shrink-0"
              style={{ background: `${palette.accent}18`, color: palette.accent, border: `1px solid ${palette.accent}30` }}
            >
              {status.artifact_type.toUpperCase()}
            </span>
            <span className="font-mono text-xs truncate" style={{ color: "var(--color-phismail-text-muted)" }}>
              {id}
            </span>
          </div>
          <span className="font-mono text-xs shrink-0" style={{ color: "var(--color-phismail-text-muted)" }}>
            {submittedAt}
          </span>
        </div>

        {/* Verdict + gauge row */}
        <div className="flex flex-col sm:flex-row items-center sm:items-start gap-6">
          <RiskGauge score={report.risk_score} verdict={report.verdict} size={130} />
          <div className="flex-1 min-w-0 text-center sm:text-left">
            <VerdictBadge verdict={report.verdict} size="lg" />
            <p className="font-mono text-xs mt-3 max-w-xl leading-relaxed" style={{ color: "var(--color-phismail-text-muted)" }}>
              {report.verdict === "PHISHING"   && "// High-confidence phishing detected. Do not interact with links or attachments. Escalate immediately."}
              {report.verdict === "SUSPICIOUS" && "// Multiple anomalous signals detected. Manual review recommended before taking any action."}
              {report.verdict === "MARKETING"  && "// Bulk marketing or transactional email. Low threat — verify sender legitimacy."}
              {report.verdict === "SAFE"        && "// No significant threat signals detected. Email appears to be from a legitimate sender."}
            </p>
            {report.phishing_probability != null && (
              <div className="mt-4 inline-flex items-center gap-2">
                <span className="font-mono text-[11px]" style={{ color: "var(--color-phismail-text-muted)" }}>phishing_prob</span>
                <div className="h-1 w-28 rounded-full overflow-hidden" style={{ background: "var(--color-phismail-border)" }}>
                  <div
                    className="h-full rounded-full"
                    style={{ width: `${(report.phishing_probability * 100).toFixed(0)}%`, background: palette.accent }}
                  />
                </div>
                <span className="font-mono text-xs font-bold" style={{ color: palette.accent }}>
                  {(report.phishing_probability * 100).toFixed(1)}%
                </span>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* ═══════════════════════════════════════════
          STATS ROW
      ═══════════════════════════════════════════ */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard
          label="Risk Score"
          value={`${Math.round(report.risk_score)}/100`}
          sub="combined suspicion"
          accent={palette.accent}
        />
        <StatCard
          label="Indicators"
          value={report.indicators.length}
          sub={`${report.indicators.filter(i => i.severity === "CRITICAL" || i.severity === "HIGH").length} high/critical`}
          accent={report.indicators.length > 0 ? "var(--color-severity-critical)" : undefined}
        />
        <StatCard
          label="URLs Analyzed"
          value={report.extracted_urls.length}
          sub={`${report.extracted_urls.filter(u => u.final_domain_mismatch).length} domain mismatch`}
        />
        <StatCard
          label="Threat Intel"
          value={report.threat_intel_hits.length}
          sub={report.threat_intel_hits.length > 0 ? "matched feeds" : "no feed matches"}
          accent={report.threat_intel_hits.length > 0 ? "var(--color-severity-critical)" : undefined}
        />
      </div>

      {/* ═══════════════════════════════════════════
          INDICATORS
      ═══════════════════════════════════════════ */}
      {report.indicators.length > 0 && (
        <section>
          <SectionHeader title="indicators_detected" count={report.indicators.length} />
          <IndicatorList indicators={report.indicators} />
        </section>
      )}

      {/* ═══════════════════════════════════════════
          TOP RISK CONTRIBUTORS
      ═══════════════════════════════════════════ */}
      {report.top_contributors.length > 0 && (
        <section>
          <SectionHeader title="top_risk_contributors" />
          <ExplainabilityChart contributors={report.top_contributors} indicators={report.indicators} />
        </section>
      )}

      {/* ═══════════════════════════════════════════
          EXTRACTED URLS
      ═══════════════════════════════════════════ */}
      {report.extracted_urls.length > 0 && (
        <section>
          <SectionHeader title="extracted_urls" count={report.extracted_urls.length} />
          <div className="space-y-3">
            {report.extracted_urls.map((u, i) => (
              <div key={i} className="glass-panel p-5 space-y-3 overflow-hidden">
                <p
                  className="font-mono text-xs leading-relaxed"
                  style={{ color: "var(--color-phismail-purple)", wordBreak: "break-all", overflowWrap: "anywhere" }}
                >
                  {u.url}
                </p>
                <div className="flex flex-wrap gap-2">
                  {u.domain && <span className="badge badge-low">{u.domain}</span>}
                  {u.redirect_count > 0 && (
                    <span className="badge badge-medium">{u.redirect_count} redirect{u.redirect_count > 1 ? "s" : ""}</span>
                  )}
                  {u.is_shortened        && <span className="badge badge-medium">Shortened</span>}
                  {u.contains_ip        && <span className="badge badge-high">IP Address</span>}
                  {u.final_domain_mismatch && <span className="badge badge-critical">Domain Mismatch</span>}
                </div>
                {u.redirect_chain && u.redirect_chain.length > 1 && (
                  <RedirectChainView
                    url={u.url}
                    redirectChain={u.redirect_chain}
                    finalDestination={u.final_destination}
                    redirectCount={u.redirect_count}
                  />
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ═══════════════════════════════════════════
          DOMAIN INTELLIGENCE + THREAT INTEL
      ═══════════════════════════════════════════ */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {report.domain_intelligence.length > 0 && (
          <section>
            <SectionHeader title="domain_intelligence" count={report.domain_intelligence.length} />
            <div className="space-y-3">
              {report.domain_intelligence.map((d, i) => (
                <DomainIntelCard key={i} domain={d} />
              ))}
            </div>
          </section>
        )}

        {report.threat_intel_hits.length > 0 && (
          <section>
            <SectionHeader title="threat_intel_hits" count={report.threat_intel_hits.length} />
            <div className="glass-panel overflow-hidden">
              {report.threat_intel_hits.map((t, i) => (
                <div
                  key={i}
                  className="px-5 py-4 flex items-start gap-4"
                  style={{ borderBottom: i < report.threat_intel_hits.length - 1 ? "1px solid var(--color-phismail-border)" : "none" }}
                >
                  <span className="badge badge-critical shrink-0 mt-0.5">{t.source}</span>
                  <div className="min-w-0 flex-1">
                    {t.matched_url && (
                      <p
                        className="font-mono text-xs"
                        style={{ color: "var(--color-phismail-text-muted)", wordBreak: "break-all", overflowWrap: "anywhere" }}
                      >
                        {t.matched_url}
                      </p>
                    )}
                    {t.confidence_score != null && (
                      <p className="font-mono text-[11px] mt-1" style={{ color: "var(--color-severity-critical)" }}>
                        confidence: {(t.confidence_score * 100).toFixed(0)}%
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}
      </div>

    </div>
  );
}
