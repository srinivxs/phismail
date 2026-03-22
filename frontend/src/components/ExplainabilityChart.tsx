"use client";

import { useState } from "react";
import type { FeatureAttribution, Indicator } from '@/lib/api';

interface ExplainabilityChartProps {
  contributors: FeatureAttribution[];
  indicators?: Indicator[];
}

const FEATURE_LABELS: Record<string, string> = {
  domain_age_days: "Domain age",
  percent_encoding_count: "URL encoding",
  url_entropy_score: "URL randomness",
  url_length: "URL length",
  return_path_mismatch: "Return-Path mismatch",
  reply_to_mismatch: "Reply-To mismatch",
  sender_domain_mismatch: "Sender domain conflict",
  spf_pass: "SPF passed",
  spf_fail: "SPF failed",
  dkim_pass: "DKIM passed",
  dkim_fail: "DKIM failed",
  dmarc_pass: "DMARC passed",
  dmarc_fail: "DMARC failed",
  num_subdomains: "Subdomain count",
  contains_ip_address: "IP in URL",
  url_shortened: "Shortened URL",
  username_in_url: "Username in URL",
  final_domain_mismatch: "Redirect mismatch",
  hidden_links_detected: "Hidden links",
  financial_request_keywords: "Financial keywords",
  credential_request_keywords: "Credential keywords",
  urgency_keyword_count: "Urgency keywords",
  threat_language_score: "Threat language",
  imperative_language_score: "Imperative language",
  brand_keyword_present: "Brand keyword",
  brand_domain_similarity_score: "Brand similarity",
  brand_homograph_detected: "Homograph attack",
  domain_recent_registration: "New domain",
  has_executable_attachment: "Executable file",
  double_extension_detected: "Double extension",
  has_macro_document: "Macro document",
  javascript_in_email: "JavaScript in email",
  redirect_count: "Redirect count",
  openphish_match: "OpenPhish match",
  phishtank_match: "PhishTank match",
  urlhaus_match: "URLhaus match",
  bulk_mail_indicator: "Bulk mail",
};

function featureLabel(name: string): string {
  return FEATURE_LABELS[name] ?? name.replaceAll('_', ' ').replace(/\b\w/g, c => c.toUpperCase());
}

export default function ExplainabilityChart({ contributors }: ExplainabilityChartProps) {
  if (!contributors || contributors.length === 0) return null;

  const maxScore = Math.max(...contributors.map(t => Math.abs(t.attribution_score)));

  /* Split into risk-increasing and risk-reducing */
  const riskUp = contributors.filter(c => c.direction === 'phishing');
  const riskDown = contributors.filter(c => c.direction === 'safe');

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* Risk increasing */}
      <div
        className="rounded-xl overflow-hidden"
        style={{ border: "1px solid var(--color-phismail-border)" }}
      >
        <div
          className="px-5 py-3 flex items-center gap-2"
          style={{
            background: "rgba(244,63,94,0.06)",
            borderBottom: "1px solid var(--color-phismail-border)",
          }}
        >
          <span className="text-xs">▲</span>
          <span
            className="text-xs font-bold font-mono uppercase tracking-wider"
            style={{ color: "#f43f5e" }}
          >
            Increases risk
          </span>
          <span
            className="text-xs font-mono ml-auto"
            style={{ color: "var(--color-phismail-text-muted)" }}
          >
            {riskUp.length}
          </span>
        </div>

        {riskUp.length === 0 ? (
          <div className="px-5 py-6 text-center">
            <p className="text-sm" style={{ color: "var(--color-phismail-text-muted)" }}>
              No risk-increasing factors
            </p>
          </div>
        ) : (
          riskUp.map((tc, i) => {
            const width = (Math.abs(tc.attribution_score) / maxScore) * 100;
            return (
              <div
                key={i}
                className="flex items-center gap-3 px-5 py-3"
                style={{
                  background: "var(--color-phismail-panel)",
                  borderBottom:
                    i < riskUp.length - 1
                      ? "1px solid var(--color-phismail-border)"
                      : "none",
                }}
              >
                <span
                  className="text-xs w-32 shrink-0 truncate"
                  style={{ color: "var(--color-phismail-text-muted)" }}
                >
                  {featureLabel(tc.feature_name)}
                </span>
                <div className="flex-1 min-w-0 h-2 rounded-full overflow-hidden" style={{ background: "var(--color-phismail-surface)" }}>
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${width}%`,
                      background: "linear-gradient(90deg, rgba(244,63,94,0.3), #f43f5e)",
                    }}
                  />
                </div>
                <span
                  className="text-xs font-bold font-mono w-14 text-right shrink-0"
                  style={{ color: "#f43f5e" }}
                >
                  +{tc.attribution_score.toFixed(1)}
                </span>
              </div>
            );
          })
        )}
      </div>

      {/* Risk reducing */}
      <div
        className="rounded-xl overflow-hidden"
        style={{ border: "1px solid var(--color-phismail-border)" }}
      >
        <div
          className="px-5 py-3 flex items-center gap-2"
          style={{
            background: "rgba(34,197,94,0.06)",
            borderBottom: "1px solid var(--color-phismail-border)",
          }}
        >
          <span className="text-xs">▼</span>
          <span
            className="text-xs font-bold font-mono uppercase tracking-wider"
            style={{ color: "#22c55e" }}
          >
            Reduces risk
          </span>
          <span
            className="text-xs font-mono ml-auto"
            style={{ color: "var(--color-phismail-text-muted)" }}
          >
            {riskDown.length}
          </span>
        </div>

        {riskDown.length === 0 ? (
          <div className="px-5 py-6 text-center">
            <p className="text-sm" style={{ color: "var(--color-phismail-text-muted)" }}>
              No risk-reducing factors
            </p>
          </div>
        ) : (
          riskDown.map((tc, i) => {
            const width = (Math.abs(tc.attribution_score) / maxScore) * 100;
            return (
              <div
                key={i}
                className="flex items-center gap-3 px-5 py-3"
                style={{
                  background: "var(--color-phismail-panel)",
                  borderBottom:
                    i < riskDown.length - 1
                      ? "1px solid var(--color-phismail-border)"
                      : "none",
                }}
              >
                <span
                  className="text-xs w-32 shrink-0 truncate"
                  style={{ color: "var(--color-phismail-text-muted)" }}
                >
                  {featureLabel(tc.feature_name)}
                </span>
                <div className="flex-1 min-w-0 h-2 rounded-full overflow-hidden" style={{ background: "var(--color-phismail-surface)" }}>
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${width}%`,
                      background: "linear-gradient(90deg, rgba(34,197,94,0.3), #22c55e)",
                    }}
                  />
                </div>
                <span
                  className="text-xs font-bold font-mono w-14 text-right shrink-0"
                  style={{ color: "#22c55e" }}
                >
                  {tc.attribution_score.toFixed(1)}
                </span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
