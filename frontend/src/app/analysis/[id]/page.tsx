"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import {
  getAnalysisStatus,
  getReport,
  type AnalysisJob,
  type InvestigationReport,
  type Indicator,
} from "@/lib/api";
import {
  VerdictBadge,
  RiskGauge,
  IndicatorList,
  ExplainabilityChart,
  RedirectChainView,
  DomainIntelCard,
  AnalysisTimeline,
} from "@/components";

/* ─── Verdict palette ─────────────────────────────────────── */
const VERDICT_PALETTE = {
  PHISHING:   { bg: "rgba(244,63,94,0.06)",  border: "rgba(244,63,94,0.26)",  accent: "#f43f5e" },
  SUSPICIOUS: { bg: "rgba(234,179,8,0.06)",  border: "rgba(234,179,8,0.24)",  accent: "#eab308" },
  MARKETING:  { bg: "rgba(167,139,250,0.06)", border: "rgba(167,139,250,0.24)", accent: "#a78bfa" },
  SAFE:       { bg: "rgba(34,197,94,0.06)",  border: "rgba(34,197,94,0.24)",  accent: "#22c55e" },
} as const;

/* ─── Plain-English verdict summaries ─────────────────────── */
const VERDICT_SUMMARY = {
  PHISHING:
    "This email shows strong signs of being a phishing attack. It likely tries to steal your credentials, install malware, or trick you into sending money. Do not click any links, open attachments, or reply. Report it to your IT/security team.",
  SUSPICIOUS:
    "Several unusual signals were detected, but they're not conclusive on their own. This could be a legitimate email with poor security practices, or a phishing attempt. Treat it with caution and verify the sender through a separate channel before taking any action.",
  MARKETING:
    "This appears to be a bulk marketing or transactional email. While not malicious, verify you recognise the sender and that you opted in to receive it. Unsubscribe if unwanted.",
  SAFE:
    "No significant threat signals were detected. The email's authentication records are consistent and no malicious URLs or content were identified. This looks like a legitimate email.",
};

/* ─── Verdict icon ────────────────────────────────────────── */
const VERDICT_ICON = {
  PHISHING:   "🚨",
  SUSPICIOUS: "⚠️",
  MARKETING:  "📢",
  SAFE:       "✅",
};

/* ─── Stat card ───────────────────────────────────────────── */
function StatCard({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
}) {
  return (
    <div
      className="rounded-xl p-5"
      style={{
        background: "var(--color-phismail-panel)",
        border: "1px solid var(--color-phismail-border)",
        backdropFilter: "blur(16px)",
      }}
    >
      <p
        className="text-[11px] font-mono font-bold uppercase tracking-widest mb-2"
        style={{ color: "var(--color-phismail-text-muted)" }}
      >
        {label}
      </p>
      <p
        className="text-3xl font-bold font-mono"
        style={{ color: accent || "var(--color-phismail-text)" }}
      >
        {value}
      </p>
      {sub && (
        <p
          className="text-xs mt-1"
          style={{ color: "var(--color-phismail-text-muted)" }}
        >
          {sub}
        </p>
      )}
    </div>
  );
}

/* ─── Section header ──────────────────────────────────────── */
function SectionHeader({
  title,
  subtitle,
  count,
}: {
  title: string;
  subtitle?: string;
  count?: number;
}) {
  return (
    <div className="flex items-baseline gap-3 mb-4">
      <h2
        className="font-bold text-base"
        style={{ color: "var(--color-phismail-text)" }}
      >
        {title}
      </h2>
      {subtitle && (
        <span
          className="text-sm"
          style={{ color: "var(--color-phismail-text-muted)" }}
        >
          {subtitle}
        </span>
      )}
      {count !== undefined && (
        <span
          className="text-xs px-2 py-0.5 rounded font-mono font-bold"
          style={{
            background: "var(--color-phismail-purple-glow)",
            color: "var(--color-phismail-purple)",
          }}
        >
          {count}
        </span>
      )}
    </div>
  );
}

/* ─── Key findings preview ────────────────────────────────── */
function KeyFindings({ indicators }: { indicators: Indicator[] }) {
  const topFindings = indicators
    .filter((i) => i.severity === "CRITICAL" || i.severity === "HIGH")
    .slice(0, 3);

  if (topFindings.length === 0) return null;

  const barColor: Record<string, string> = {
    CRITICAL: "#f43f5e",
    HIGH: "#f97316",
  };

  return (
    <div
      className="rounded-xl overflow-hidden"
      style={{ border: "1px solid var(--color-phismail-border)" }}
    >
      {topFindings.map((ind, i) => (
        <div
          key={i}
          className="flex gap-0"
          style={{
            borderBottom:
              i < topFindings.length - 1
                ? "1px solid var(--color-phismail-border)"
                : "none",
            background: "var(--color-phismail-panel)",
          }}
        >
          <div
            style={{
              width: 4,
              flexShrink: 0,
              background: barColor[ind.severity] ?? "#94a3b8",
            }}
          />
          <div className="flex-1 px-5 py-4">
            <div className="flex items-start gap-3">
              <span className={`badge badge-${ind.severity.toLowerCase()} shrink-0 mt-0.5`}>
                {ind.severity}
              </span>
              <div>
                <p
                  className="font-semibold text-sm"
                  style={{ color: "var(--color-phismail-text)" }}
                >
                  {ind.indicator_type.replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase())}
                </p>
                {ind.detail && (
                  <p
                    className="text-xs mt-0.5 leading-relaxed"
                    style={{ color: "var(--color-phismail-text-muted)" }}
                  >
                    {ind.detail}
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── Main page ───────────────────────────────────────────── */
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

  /* Error */
  if (error) {
    return (
      <div className="max-w-2xl mx-auto mt-10">
        <div
          className="rounded-xl p-8 text-center"
          style={{
            background: "rgba(244,63,94,0.06)",
            border: "1px solid rgba(244,63,94,0.26)",
          }}
        >
          <p className="text-2xl mb-3">⚠️</p>
          <p
            className="font-semibold"
            style={{ color: "var(--color-severity-critical)" }}
          >
            {error}
          </p>
        </div>
      </div>
    );
  }

  /* Skeleton */
  if (!status) {
    return (
      <div className="space-y-4 pt-8">
        <div className="h-40 loading-shimmer rounded-xl" />
        <div className="h-24 loading-shimmer rounded-xl" />
        <div className="h-64 loading-shimmer rounded-xl" />
      </div>
    );
  }

  /* Processing / Pending */
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

  /* Failed */
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

  if (!report) {
    return <div className="h-64 loading-shimmer rounded-xl mt-8" />;
  }

  const palette = VERDICT_PALETTE[report.verdict] ?? VERDICT_PALETTE.SAFE;
  const submittedAt = report.created_at
    ? new Date(report.created_at).toLocaleString()
    : "—";
  const verdictIcon = VERDICT_ICON[report.verdict] ?? "🔍";
  const verdictSummary = VERDICT_SUMMARY[report.verdict];

  const criticalAndHighCount = report.indicators.filter(
    (i) => i.severity === "CRITICAL" || i.severity === "HIGH"
  ).length;

  return (
    <div className="space-y-6 pt-8">

      {/* ═══════════════════════════════════════════
          VERDICT BANNER
      ═══════════════════════════════════════════ */}
      <section
        className="rounded-2xl p-6 md:p-8 overflow-hidden"
        style={{
          background: palette.bg,
          border: `1px solid ${palette.border}`,
          backdropFilter: "blur(16px)",
        }}
      >
        {/* Meta row */}
        <div
          className="flex flex-wrap items-center justify-between gap-3 mb-6 pb-5"
          style={{ borderBottom: `1px solid ${palette.border}` }}
        >
          <div className="flex items-center gap-3 min-w-0">
            <span
              className="text-[10px] font-mono font-bold uppercase tracking-widest px-2.5 py-1 rounded"
              style={{
                background: `${palette.accent}18`,
                color: palette.accent,
                border: `1px solid ${palette.accent}30`,
              }}
            >
              {status.artifact_type.toUpperCase()}
            </span>
            <span
              className="font-mono text-xs truncate"
              style={{ color: "var(--color-phismail-text-muted)" }}
            >
              {id}
            </span>
          </div>
          <span
            className="font-mono text-xs shrink-0"
            style={{ color: "var(--color-phismail-text-muted)" }}
          >
            {submittedAt}
          </span>
        </div>

        {/* Verdict + gauge row */}
        <div className="flex flex-col md:flex-row items-center md:items-start gap-8">
          <RiskGauge score={report.risk_score} verdict={report.verdict} size={130} />

          <div className="flex-1 min-w-0 text-center md:text-left">
            {/* Verdict headline */}
            <div className="flex items-center gap-3 justify-center md:justify-start mb-3">
              <span className="text-3xl">{verdictIcon}</span>
              <VerdictBadge verdict={report.verdict} size="lg" />
            </div>

            {/* Plain-English explanation */}
            <p
              className="text-sm leading-relaxed max-w-xl mb-4"
              style={{ color: "var(--color-phismail-text-muted)" }}
            >
              {verdictSummary}
            </p>

            {/* Phishing probability bar */}
            {report.phishing_probability != null && (
              <div className="inline-flex flex-col gap-1.5">
                <div className="flex items-center gap-3">
                  <span
                    className="text-xs font-mono"
                    style={{ color: "var(--color-phismail-text-muted)" }}
                  >
                    Phishing probability
                  </span>
                  <span
                    className="text-sm font-bold font-mono"
                    style={{ color: palette.accent }}
                  >
                    {(report.phishing_probability * 100).toFixed(1)}%
                  </span>
                </div>
                <div
                  className="h-1.5 w-48 rounded-full overflow-hidden"
                  style={{ background: "rgba(255,255,255,0.08)" }}
                >
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{
                      width: `${(report.phishing_probability * 100).toFixed(0)}%`,
                      background: palette.accent,
                      boxShadow: `0 0 8px ${palette.accent}60`,
                    }}
                  />
                </div>
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
          sub={`${criticalAndHighCount} critical/high`}
          accent={
            criticalAndHighCount > 0
              ? "var(--color-severity-critical)"
              : undefined
          }
        />
        <StatCard
          label="URLs Analyzed"
          value={report.extracted_urls.length}
          sub={`${report.extracted_urls.filter((u) => u.final_domain_mismatch).length} domain mismatch`}
        />
        <StatCard
          label="Threat Intel Hits"
          value={report.threat_intel_hits.length}
          sub={
            report.threat_intel_hits.length > 0
              ? "matched live feeds"
              : "no feed matches"
          }
          accent={
            report.threat_intel_hits.length > 0
              ? "var(--color-severity-critical)"
              : undefined
          }
        />
      </div>

      {/* ═══════════════════════════════════════════
          KEY FINDINGS (learner-focused top signals)
      ═══════════════════════════════════════════ */}
      {criticalAndHighCount > 0 && (
        <section>
          <SectionHeader
            title="Key findings"
            subtitle="— the signals that most influenced the verdict"
          />
          <KeyFindings indicators={report.indicators} />
        </section>
      )}

      {/* ═══════════════════════════════════════════
          ALL INDICATORS (full evidence board)
      ═══════════════════════════════════════════ */}
      {report.indicators.length > 0 && (
        <section>
          <SectionHeader
            title="All indicators"
            subtitle="— click any row to learn what it means"
            count={report.indicators.length}
          />
          <IndicatorList indicators={report.indicators} />
        </section>
      )}

      {/* ═══════════════════════════════════════════
          TOP RISK CONTRIBUTORS
      ═══════════════════════════════════════════ */}
      {report.top_contributors.length > 0 && (
        <section>
          <SectionHeader
            title="Risk score breakdown"
            subtitle="— what drove the score up or down"
          />
          <ExplainabilityChart
            contributors={report.top_contributors}
            indicators={report.indicators}
          />
        </section>
      )}

      {/* ═══════════════════════════════════════════
          EXTRACTED URLS
      ═══════════════════════════════════════════ */}
      {report.extracted_urls.length > 0 && (
        <section>
          <SectionHeader
            title="URLs found"
            count={report.extracted_urls.length}
          />
          <div className="space-y-3">
            {report.extracted_urls.map((u, i) => (
              <div key={i} className="glass-panel p-5 space-y-3 overflow-hidden">
                <p
                  className="font-mono text-xs leading-relaxed break-all"
                  style={{ color: "var(--color-phismail-purple)" }}
                >
                  {u.url}
                </p>
                <div className="flex flex-wrap gap-2">
                  {u.domain && (
                    <span className="badge badge-low">{u.domain}</span>
                  )}
                  {u.redirect_count > 0 && (
                    <span className="badge badge-medium">
                      {u.redirect_count} redirect
                      {u.redirect_count > 1 ? "s" : ""}
                    </span>
                  )}
                  {u.is_shortened && (
                    <span className="badge badge-medium">Shortened URL</span>
                  )}
                  {u.contains_ip && (
                    <span className="badge badge-high">IP Address</span>
                  )}
                  {u.final_domain_mismatch && (
                    <span className="badge badge-critical">Domain Mismatch</span>
                  )}
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
            <SectionHeader
              title="Domain intelligence"
              count={report.domain_intelligence.length}
            />
            <div className="space-y-3">
              {report.domain_intelligence.map((d, i) => (
                <DomainIntelCard key={i} domain={d} />
              ))}
            </div>
          </section>
        )}

        {report.threat_intel_hits.length > 0 && (
          <section>
            <SectionHeader
              title="Threat intel hits"
              count={report.threat_intel_hits.length}
            />
            <div className="glass-panel overflow-hidden">
              {report.threat_intel_hits.map((t, i) => (
                <div
                  key={i}
                  className="px-5 py-4 flex items-start gap-4"
                  style={{
                    borderBottom:
                      i < report.threat_intel_hits.length - 1
                        ? "1px solid var(--color-phismail-border)"
                        : "none",
                  }}
                >
                  <span className="badge badge-critical shrink-0 mt-0.5">
                    {t.source}
                  </span>
                  <div className="min-w-0 flex-1">
                    {t.matched_url && (
                      <p
                        className="font-mono text-xs break-all"
                        style={{ color: "var(--color-phismail-text-muted)" }}
                      >
                        {t.matched_url}
                      </p>
                    )}
                    {t.confidence_score != null && (
                      <p
                        className="font-mono text-[11px] mt-1"
                        style={{ color: "var(--color-severity-critical)" }}
                      >
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
