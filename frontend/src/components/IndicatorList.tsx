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

const severityBar: Record<string, string> = {
  CRITICAL: "#f43f5e",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#22c55e",
};

/* Plain-language labels and explanations for each indicator type */
const INDICATOR_INFO: Record<string, { label: string; explanation: string }> = {
  spf_fail: {
    label: "SPF authentication failed",
    explanation: "SPF (Sender Policy Framework) verifies that the mail server is authorized to send email for this domain. A failure means the email likely wasn't sent by who it claims to be — a core sign of spoofing.",
  },
  dkim_fail: {
    label: "DKIM signature invalid",
    explanation: "DKIM (DomainKeys Identified Mail) cryptographically signs emails to prove they haven't been altered in transit. An invalid signature means the email may be forged or tampered with.",
  },
  dmarc_fail: {
    label: "DMARC policy violation",
    explanation: "DMARC ties SPF and DKIM together and tells receiving servers what to do when checks fail. A DMARC failure means the sender's domain couldn't be verified by either method.",
  },
  reply_to_mismatch: {
    label: "Reply-To address mismatch",
    explanation: "The Reply-To address uses a different domain than the From address. Attackers do this to intercept your reply while appearing to come from a trusted source — one of the most reliable phishing signals.",
  },
  return_path_mismatch: {
    label: "Return-Path domain mismatch",
    explanation: "The bounce address (Return-Path) belongs to a different domain than the sender. Legitimate senders keep these consistent — a mismatch suggests the email infrastructure is being spoofed.",
  },
  sender_domain_mismatch: {
    label: "Sender domain inconsistency",
    explanation: "The From, Reply-To, and Return-Path headers reference different domains. All three should agree on who sent the email. Conflicting domains indicate header spoofing.",
  },
  homograph_domain: {
    label: "Homograph / lookalike domain",
    explanation: "The domain uses Unicode characters that look visually identical to standard letters (e.g. Cyrillic 'а' instead of Latin 'a'). These are called homograph attacks — the URL looks legitimate but isn't.",
  },
  typosquat_domain: {
    label: "Typosquatting domain detected",
    explanation: "The domain closely resembles a well-known brand name with a small misspelling (e.g. paypa1.com, g00gle.net). These are registered to deceive users who don't inspect URLs carefully.",
  },
  brand_impersonation: {
    label: "Brand impersonation",
    explanation: "A trusted brand name (PayPal, Microsoft, Apple, etc.) appears in the domain or email content in a deceptive way. Attackers use brand names to borrow the trust users have in those companies.",
  },
  new_domain: {
    label: "Recently registered domain",
    explanation: "The sending domain was registered very recently. Attackers register fresh domains for each campaign specifically because new domains have no spam reputation history.",
  },
  url_contains_ip: {
    label: "IP address used instead of domain",
    explanation: "The URL uses a raw IP address (e.g. http://192.168.1.1/login) instead of a domain name. Legitimate services never do this — using an IP bypasses DNS-based blocklists.",
  },
  url_shortened: {
    label: "Shortened URL detected",
    explanation: "A URL shortener (bit.ly, tinyurl, etc.) was used to hide the true destination. Users and security tools can't inspect where the link leads without following it.",
  },
  redirect_chain: {
    label: "Multi-hop redirect chain",
    explanation: "The URL goes through multiple redirects before reaching its destination. This is used to route traffic through legitimate-looking domains before landing on the phishing page.",
  },
  final_domain_mismatch: {
    label: "Redirect destination mismatch",
    explanation: "After following all redirects, the final destination domain is different from the original link. The original URL appeared safe but ultimately delivered the user to a different, potentially malicious site.",
  },
  executable_attachment: {
    label: "Executable attachment",
    explanation: "An executable file (.exe, .bat, .cmd, .scr) is attached to the email. Legitimate businesses never send executables via email — this is a primary malware delivery mechanism.",
  },
  double_extension: {
    label: "Double extension file",
    explanation: "An attachment uses a misleading double extension (e.g. invoice.pdf.exe). Windows hides known extensions by default, making this appear as 'invoice.pdf' — a classic malware disguise.",
  },
  macro_document: {
    label: "Macro-enabled Office document",
    explanation: "An attached Office document contains embedded macros. When the victim enables macros, arbitrary code runs silently. This is one of the most common malware delivery methods.",
  },
  urgency_language: {
    label: "Urgency language detected",
    explanation: "Words and phrases designed to create time pressure ('immediately', 'final notice', 'action required') were found. Artificial urgency short-circuits careful decision-making — a core social engineering tactic.",
  },
  credential_request: {
    label: "Credential harvesting language",
    explanation: "Phrases that prompt you to enter login details ('verify your account', 'confirm your password') were detected. These direct victims to fake login pages designed to capture credentials.",
  },
  financial_language: {
    label: "Financial manipulation language",
    explanation: "Financial trigger words ('wire transfer', 'invoice', 'payment failed') were found. These create fear around money to bypass rational thinking and prompt immediate action.",
  },
  threat_intel_match: {
    label: "URL matched threat intelligence feed",
    explanation: "One or more URLs in this email were found in real-time phishing or malware feeds (OpenPhish, PhishTank, URLHaus). These feeds are maintained by the security community and list known-malicious URLs.",
  },
  javascript_in_email: {
    label: "JavaScript in email body",
    explanation: "JavaScript code was found inside the email HTML. Legitimate emails never contain JavaScript. Its presence suggests an attempt to run code in your email client to steal data or redirect you.",
  },
};

function humanLabel(indicatorType: string): string {
  return INDICATOR_INFO[indicatorType]?.label
    ?? indicatorType.replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function Explanation({ indicatorType, detail }: { indicatorType: string; detail?: string }) {
  const info = INDICATOR_INFO[indicatorType];
  if (!info && !detail) return null;

  return (
    <div className="mt-3 space-y-2">
      {detail && (
        <div
          className="rounded-lg p-3 text-sm"
          style={{
            background: "rgba(245,158,11,0.05)",
            border: "1px solid rgba(245,158,11,0.15)",
          }}
        >
          <p
            className="text-xs font-mono font-bold uppercase tracking-wider mb-1"
            style={{ color: "var(--color-phismail-purple)" }}
          >
            Finding in this email
          </p>
          <p style={{ color: "var(--color-phismail-text)", lineHeight: 1.6 }}>{detail}</p>
        </div>
      )}
      {info?.explanation && (
        <div className="edu-callout text-sm">
          <p
            className="text-xs font-mono font-bold uppercase tracking-wider mb-1"
            style={{ color: "var(--color-phismail-green)" }}
          >
            What this means
          </p>
          {info.explanation}
        </div>
      )}
    </div>
  );
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
        <p className="text-2xl mb-2">✅</p>
        <p className="font-semibold" style={{ color: "var(--color-phismail-text)" }}>
          No indicators detected
        </p>
        <p className="text-sm mt-1" style={{ color: "var(--color-phismail-text-muted)" }}>
          No suspicious signals were found in this analysis.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {sorted.map((ind, i) => {
        const isOpen = expandedIdx === i;
        const barColor = severityBar[ind.severity] ?? "#94a3b8";
        const hasExplanation =
          !!ind.detail || !!INDICATOR_INFO[ind.indicator_type];

        return (
          <div key={i} className="evidence-item">
            {/* Severity bar */}
            <div
              className="evidence-item-bar"
              style={{ background: barColor }}
            />

            <div className="evidence-item-content">
              <button
                className="w-full text-left"
                onClick={() =>
                  hasExplanation && setExpandedIdx(isOpen ? null : i)
                }
                style={{ cursor: hasExplanation ? "pointer" : "default" }}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-3 min-w-0 flex-1">
                    <span
                      className={`badge badge-${ind.severity.toLowerCase()} shrink-0 mt-0.5`}
                    >
                      {ind.severity}
                    </span>
                    <div className="min-w-0">
                      <p
                        className="font-semibold text-sm leading-snug"
                        style={{ color: "var(--color-phismail-text)" }}
                      >
                        {humanLabel(ind.indicator_type)}
                      </p>
                      {ind.detail && !isOpen && (
                        <p
                          className="text-xs mt-0.5 truncate"
                          style={{ color: "var(--color-phismail-text-muted)" }}
                        >
                          {ind.detail}
                        </p>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    {ind.confidence !== undefined && ind.confidence !== null && (
                      <span
                        className="text-xs font-mono"
                        style={{ color: "var(--color-phismail-text-muted)" }}
                      >
                        {(ind.confidence * 100).toFixed(0)}% conf
                      </span>
                    )}
                    {hasExplanation && (
                      <span
                        className="text-xs font-mono"
                        style={{ color: "var(--color-phismail-green)" }}
                      >
                        {isOpen ? "▲ less" : "▼ explain"}
                      </span>
                    )}
                  </div>
                </div>
              </button>

              {isOpen && (
                <Explanation
                  indicatorType={ind.indicator_type}
                  detail={ind.detail}
                />
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
