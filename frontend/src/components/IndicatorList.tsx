"use client";

import { useState } from "react";
import type { Indicator } from "@/lib/api";

interface IndicatorListProps {
  indicators: Indicator[];
}

const severityOrder: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
};

const severityColor: Record<string, string> = {
  CRITICAL: "#f43f5e",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#22c55e",
};

/* Concise, actionable explanations per indicator type */
const INDICATOR_INFO: Record<string, { label: string; risk: string; action: string }> = {
  spf_fail: {
    label: "SPF failed",
    risk: "The sending server is not authorized for this domain. High spoofing likelihood.",
    action: "Do not trust the sender identity. Verify through a separate channel.",
  },
  dkim_fail: {
    label: "DKIM invalid",
    risk: "Email signature verification failed. Message may be forged or altered in transit.",
    action: "Treat content as potentially tampered. Do not click links or open attachments.",
  },
  dmarc_fail: {
    label: "DMARC failed",
    risk: "Domain authentication failed both SPF and DKIM checks.",
    action: "Strong spoofing signal. Report to your security team.",
  },
  reply_to_mismatch: {
    label: "Reply-To mismatch",
    risk: "Reply address points to a different domain than the sender. Replies would go to the attacker.",
    action: "Never reply directly. Contact the supposed sender through official channels.",
  },
  return_path_mismatch: {
    label: "Return-Path mismatch",
    risk: "Bounce address uses a different domain. Infrastructure is inconsistent with claimed sender.",
    action: "Indicates mail system spoofing. Cross-reference with known sender domains.",
  },
  sender_domain_mismatch: {
    label: "Sender domain conflict",
    risk: "From, Reply-To, and Return-Path headers reference different domains.",
    action: "Multiple conflicting identities is a strong spoofing indicator.",
  },
  homograph_domain: {
    label: "Homograph domain",
    risk: "Domain uses lookalike Unicode characters (e.g. Cyrillic 'a' vs Latin 'a').",
    action: "Visually deceptive. Copy-paste the domain into a text editor to reveal hidden characters.",
  },
  typosquat_domain: {
    label: "Typosquat detected",
    risk: "Domain closely mimics a known brand with subtle misspelling.",
    action: "Compare character-by-character against the real domain. Block this domain.",
  },
  brand_impersonation: {
    label: "Brand impersonation",
    risk: "Trusted brand name used deceptively in the domain or content.",
    action: "Go to the brand's official website directly. Do not follow links from this email.",
  },
  new_domain: {
    label: "New domain",
    risk: "Domain registered recently. Fresh domains are commonly used in phishing campaigns.",
    action: "Newly registered + unsolicited email = high risk. Treat with extreme caution.",
  },
  url_contains_ip: {
    label: "IP address in URL",
    risk: "URL uses a raw IP instead of a domain. Legitimate services never do this.",
    action: "Do not visit. IP-based URLs bypass DNS blocklists and hide the operator.",
  },
  url_shortened: {
    label: "Shortened URL",
    risk: "Link shortener hides the true destination. Cannot verify safety without following.",
    action: "Use a URL expander tool before clicking. PhisMail traces these automatically.",
  },
  redirect_chain: {
    label: "Redirect chain",
    risk: "URL bounces through multiple servers before reaching destination.",
    action: "Each hop can mask the final landing page. Check the final destination domain.",
  },
  final_domain_mismatch: {
    label: "Redirect destination mismatch",
    risk: "After all redirects, the final domain differs from the original link.",
    action: "The displayed link is deceptive. The actual destination is different.",
  },
  executable_attachment: {
    label: "Executable attachment",
    risk: "Contains .exe, .bat, .cmd, or .scr file. Primary malware delivery method.",
    action: "Never open executable attachments from email. Delete immediately.",
  },
  double_extension: {
    label: "Double extension",
    risk: "File uses misleading extension (e.g. invoice.pdf.exe appears as invoice.pdf).",
    action: "Enable 'show file extensions' in your OS. Do not open this file.",
  },
  macro_document: {
    label: "Macro document",
    risk: "Office file contains embedded macros that can execute arbitrary code.",
    action: "Never enable macros from untrusted sources. Report the attachment.",
  },
  urgency_language: {
    label: "Urgency language",
    risk: "Time-pressure phrases detected: 'immediately', 'final notice', 'act now'.",
    action: "Artificial urgency is designed to prevent you from thinking critically. Slow down.",
  },
  credential_request: {
    label: "Credential harvesting",
    risk: "Prompts to enter login details: 'verify your account', 'confirm password'.",
    action: "Never enter credentials from an email link. Go to the service directly via your browser.",
  },
  financial_language: {
    label: "Financial trigger",
    risk: "Payment-related language detected: 'wire transfer', 'invoice', 'payment failed'.",
    action: "Verify through your financial institution directly. Do not act on email instructions.",
  },
  threat_intel_match: {
    label: "Threat feed match",
    risk: "URL found in active phishing/malware feeds (OpenPhish, PhishTank, URLHaus).",
    action: "Confirmed malicious. Do not visit. Block the domain organization-wide.",
  },
  javascript_in_email: {
    label: "JavaScript in email",
    risk: "Script code detected in email HTML. Legitimate emails never contain JavaScript.",
    action: "Potential XSS or redirect attack. Do not interact with this email.",
  },
};

function humanLabel(indicatorType: string): string {
  return INDICATOR_INFO[indicatorType]?.label
    ?? indicatorType.replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export default function IndicatorList({ indicators }: IndicatorListProps) {
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);

  const sorted = [...indicators].sort(
    (a, b) => (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99)
  );

  if (sorted.length === 0) {
    return (
      <div
        className="rounded-xl p-10 text-center"
        style={{
          background: "var(--color-phismail-surface)",
          border: "1px solid var(--color-phismail-border)",
        }}
      >
        <p className="text-2xl mb-2">No indicators detected</p>
        <p className="text-sm" style={{ color: "var(--color-phismail-text-muted)" }}>
          No suspicious signals found in this analysis.
        </p>
      </div>
    );
  }

  return (
    <div
      className="rounded-xl overflow-hidden"
      style={{ border: "1px solid var(--color-phismail-border)" }}
    >
      {sorted.map((ind, i) => {
        const isOpen = expandedIdx === i;
        const color = severityColor[ind.severity] ?? "#94a3b8";
        const info = INDICATOR_INFO[ind.indicator_type];
        const hasDetail = !!ind.detail || !!info;

        return (
          <div
            key={i}
            style={{
              borderBottom:
                i < sorted.length - 1
                  ? "1px solid var(--color-phismail-border)"
                  : "none",
            }}
          >
            <button
              className="w-full text-left flex items-center gap-4 px-5 py-3.5 transition-colors"
              onClick={() => hasDetail && setExpandedIdx(isOpen ? null : i)}
              style={{
                cursor: hasDetail ? "pointer" : "default",
                background: isOpen ? "var(--color-phismail-surface)" : "var(--color-phismail-panel)",
              }}
            >
              {/* Severity dot */}
              <span
                className="w-2.5 h-2.5 rounded-full shrink-0"
                style={{ background: color, boxShadow: `0 0 6px ${color}40` }}
              />

              {/* Label */}
              <span
                className="flex-1 text-sm font-medium min-w-0 truncate"
                style={{ color: "var(--color-phismail-text)" }}
              >
                {humanLabel(ind.indicator_type)}
              </span>

              {/* Severity tag */}
              <span
                className="text-[10px] font-bold font-mono uppercase px-2 py-0.5 rounded shrink-0"
                style={{
                  color: color,
                  background: `${color}15`,
                  border: `1px solid ${color}30`,
                }}
              >
                {ind.severity}
              </span>

              {/* Confidence */}
              {ind.confidence != null && (
                <span
                  className="text-xs font-mono shrink-0"
                  style={{ color: "var(--color-phismail-text-muted)" }}
                >
                  {(ind.confidence * 100).toFixed(0)}%
                </span>
              )}

              {/* Expand arrow */}
              {hasDetail && (
                <span
                  className="text-[10px] shrink-0 transition-transform"
                  style={{
                    color: "var(--color-phismail-text-muted)",
                    transform: isOpen ? "rotate(180deg)" : "rotate(0deg)",
                  }}
                >
                  ▼
                </span>
              )}
            </button>

            {/* Expanded detail */}
            {isOpen && (
              <div
                className="px-5 pb-4 pt-1"
                style={{ background: "var(--color-phismail-surface)" }}
              >
                {/* Finding in this email */}
                {ind.detail && (
                  <div
                    className="rounded-lg px-4 py-3 mb-2.5 text-sm leading-relaxed"
                    style={{
                      background: `${color}08`,
                      borderLeft: `3px solid ${color}`,
                      color: "var(--color-phismail-text)",
                    }}
                  >
                    {ind.detail}
                  </div>
                )}

                {/* Risk + Action */}
                {info && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                    <div
                      className="rounded-lg px-4 py-3 text-sm"
                      style={{
                        background: "var(--color-phismail-panel)",
                        border: "1px solid var(--color-phismail-border)",
                      }}
                    >
                      <p
                        className="text-[10px] font-bold font-mono uppercase tracking-wider mb-1.5"
                        style={{ color: color }}
                      >
                        Risk
                      </p>
                      <p className="leading-relaxed" style={{ color: "var(--color-phismail-text-muted)" }}>
                        {info.risk}
                      </p>
                    </div>
                    <div
                      className="rounded-lg px-4 py-3 text-sm"
                      style={{
                        background: "var(--color-phismail-panel)",
                        border: "1px solid var(--color-phismail-border)",
                      }}
                    >
                      <p
                        className="text-[10px] font-bold font-mono uppercase tracking-wider mb-1.5"
                        style={{ color: "var(--color-phismail-green)" }}
                      >
                        What to do
                      </p>
                      <p className="leading-relaxed" style={{ color: "var(--color-phismail-text-muted)" }}>
                        {info.action}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
