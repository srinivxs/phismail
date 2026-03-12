"use client";

import { useState } from "react";
import type { FeatureAttribution, Indicator } from '@/lib/api';

interface ExplainabilityChartProps {
  contributors: FeatureAttribution[];
  indicators?: Indicator[];
}

const FEATURE_DESCRIPTIONS: Record<string, { what: string; why: string }> = {
  domain_age_days: {
    what: "Number of days since the domain was first registered.",
    why: "Older domains are generally more trustworthy. A negative contribution here means the domain is well-established, reducing phishing risk. Newly registered domains are a major red flag.",
  },
  percent_encoding_count: {
    what: "Number of percent-encoded characters (e.g. %2F, %40) found in the URL.",
    why: "Percent encoding is used to disguise special characters and bypass URL scanners. Attackers encode characters like '/', '@', and '.' to hide the true structure of a malicious URL.",
  },
  url_entropy_score: {
    what: "A measure of randomness in the URL path (higher = more random).",
    why: "High entropy indicates machine-generated or obfuscated URLs. Phishing links often contain long random strings to evade detection while hiding the destination.",
  },
  url_length: {
    what: "Total character length of the URL.",
    why: "Excessively long URLs are used to bury the real domain name deep in the path, making it hard for users to spot where they are actually being sent.",
  },
  return_path_mismatch: {
    what: "The Return-Path header (bounce address) uses a different domain than the From address.",
    why: "Legitimate senders keep these consistent. A mismatch suggests the email infrastructure is being spoofed or hijacked — a classic phishing indicator.",
  },
  reply_to_mismatch: {
    what: "The Reply-To address uses a different domain than the From address.",
    why: "Attackers set a different Reply-To to intercept your response while appearing to come from a trusted sender. This is one of the most reliable phishing signals.",
  },
  sender_domain_mismatch: {
    what: "The From, Reply-To, and Return-Path headers reference different domains.",
    why: "All three headers should agree on who sent the email. Conflicting domains indicate header spoofing — the sender is not who they claim to be.",
  },
  spf_pass: {
    what: "SPF (Sender Policy Framework) authentication passed.",
    why: "SPF verifies that the sending server is authorised to send email for the domain. A pass reduces the likelihood this is a spoofed or forged email.",
  },
  dkim_pass: {
    what: "DKIM (DomainKeys Identified Mail) signature verified successfully.",
    why: "DKIM cryptographically signs the email, proving it hasn't been tampered with in transit. A passing signature is a strong legitimacy signal.",
  },
  dmarc_pass: {
    what: "DMARC policy check passed for the sender domain.",
    why: "DMARC ties SPF and DKIM together and tells receiving servers what to do with failures. A pass means the domain owner's policy is being enforced.",
  },
  num_subdomains: {
    what: "Number of subdomain levels in the URL (e.g. a.b.c.evil.com = 3 subdomains).",
    why: "Attackers stack subdomains to make URLs look legitimate — e.g. 'secure.login.paypal.evil.com' — while the actual registered domain (evil.com) is malicious.",
  },
  contains_ip_address: {
    what: "The URL uses a raw IP address instead of a domain name.",
    why: "Legitimate services never send links to bare IP addresses. Using an IP avoids DNS-based blocklists and hides the true operator of the server.",
  },
  url_shortened: {
    what: "The URL uses a known link-shortening service.",
    why: "Shortened URLs hide the true destination. Users and security tools cannot inspect where the link leads without following it.",
  },
  username_in_url: {
    what: "The URL contains a username/credentials segment (e.g. https://paypal.com@evil.com).",
    why: "The domain shown before the '@' is just a username in the URL, not the actual destination. The real destination is after it. This is a classic URL deception technique.",
  },
  final_domain_mismatch: {
    what: "The domain after following all redirects differs from the original link.",
    why: "Multi-hop redirect chains are used to bypass link scanners. The original URL appears safe but ultimately delivers the user to a phishing page.",
  },
  hidden_links_detected: {
    what: "Hyperlinks whose visible display text doesn't match their actual destination URL.",
    why: "A link showing 'www.paypal.com' that actually points to 'evil.ru' is a core phishing technique to deceive users into clicking malicious links.",
  },
  financial_request_keywords: {
    what: "Count of financial-related phishing keywords found in the email (e.g. 'wire transfer', 'invoice', 'payment failed').",
    why: "Financial language creates urgency and fear around money. Phishers use it to trigger panic responses, bypassing critical thinking.",
  },
  credential_request_keywords: {
    what: "Count of credential-harvesting phrases (e.g. 'verify your account', 'enter your password').",
    why: "These phrases are designed to prompt users to submit their login credentials to a fake page under the guise of security or account verification.",
  },
  urgency_keyword_count: {
    what: "Number of urgency-inducing words found (e.g. 'immediately', 'final notice', 'action required').",
    why: "Urgency language short-circuits careful decision-making. Phishers create artificial time pressure to prevent victims from verifying the email's legitimacy.",
  },
  threat_language_score: {
    what: "A composite score combining all detected social engineering language signals.",
    why: "The higher this score, the more the email relies on psychological manipulation tactics — urgency, fear, authority, and scarcity — all hallmarks of phishing.",
  },
  imperative_language_score: {
    what: "Frequency of commanding phrases like 'click here', 'download now', 'verify immediately'.",
    why: "Imperative language pushes users to take action without pausing to think. It's used to drive clicks on malicious links or attachments.",
  },
  brand_keyword_present: {
    what: "A known brand name (e.g. PayPal, Microsoft, Apple) appears in the domain or email content.",
    why: "Impersonating trusted brands gives phishing emails credibility. Users are more likely to comply with requests that appear to come from services they recognise.",
  },
  brand_domain_similarity_score: {
    what: "How closely the domain resembles a known brand name (0.0 = no match, 1.0 = identical).",
    why: "A high similarity score indicates a typosquat or lookalike domain (e.g. 'paypa1.com'). These are registered to exploit users who don't closely examine URLs.",
  },
  brand_homograph_detected: {
    what: "The domain uses Unicode characters that visually mimic ASCII letters.",
    why: "Homograph attacks use characters like Cyrillic 'а' (looks identical to Latin 'a') to create domains that are visually indistinguishable from legitimate ones.",
  },
  domain_recent_registration: {
    what: "The domain was registered very recently (within the last 30–90 days).",
    why: "Attackers register fresh domains specifically for phishing campaigns. New domains have no reputation history, making them ideal for bypassing blocklists.",
  },
  has_executable_attachment: {
    what: "An executable file (.exe, .bat, .cmd, .scr, etc.) is attached to the email.",
    why: "Executable attachments are a primary malware delivery mechanism. Legitimate businesses never send executables via email.",
  },
  double_extension_detected: {
    what: "An attachment has a misleading double extension (e.g. invoice.pdf.exe).",
    why: "Double extensions exploit OS defaults that hide known extensions, making 'invoice.pdf.exe' appear as 'invoice.pdf' — a classic malware disguise.",
  },
  has_macro_document: {
    what: "An Office document attachment (Word, Excel) contains embedded macros.",
    why: "Macro-enabled documents are one of the most common malware delivery methods. When opened and macros are enabled, arbitrary code can execute silently.",
  },
  javascript_in_email: {
    what: "JavaScript code was detected inside the email body HTML.",
    why: "Legitimate emails do not contain JavaScript. Its presence in an email suggests an attempt to run code in the email client, potentially stealing data or redirecting the user.",
  },
  redirect_count: {
    what: "Number of HTTP redirects the URL goes through before reaching its final destination.",
    why: "Multiple redirects obscure the true destination. Each hop can be used to route through legitimate-looking domains before landing on the phishing page.",
  },
  openphish_match: {
    what: "The URL appears in the OpenPhish real-time phishing feed.",
    why: "OpenPhish is a community-curated list of actively reported phishing URLs. A match means this URL has already been identified as malicious.",
  },
  phishtank_match: {
    what: "The URL is listed in the PhishTank verified phishing database.",
    why: "PhishTank is a community-verified phishing URL database. Matches are confirmed phishing sites.",
  },
  urlhaus_match: {
    what: "The URL appears in the URLhaus malware distribution feed.",
    why: "URLhaus tracks URLs used to distribute malware. A match indicates this URL has been reported for malware hosting.",
  },
};

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: 'bg-red-500/10 text-red-400 border border-red-500/30',
  HIGH: 'bg-orange-500/10 text-orange-400 border border-orange-500/30',
  MEDIUM: 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30',
  LOW: 'bg-blue-500/10 text-blue-400 border border-blue-500/30',
};

export default function ExplainabilityChart({ contributors, indicators = [] }: ExplainabilityChartProps) {
  const [expanded, setExpanded] = useState<number | null>(null);

  if (!contributors || contributors.length === 0) return null;

  // Build a lookup: feature_name → indicator (for file-specific findings)
  const indicatorMap = new Map<string, Indicator>();
  for (const ind of indicators) {
    indicatorMap.set(ind.indicator_type, ind);
  }

  const maxScore = Math.max(...contributors.map(t => Math.abs(t.attribution_score)));

  return (
    <section>
      <div className="glass-panel divide-y divide-[var(--color-phismail-border)]">
        {contributors.map((tc, i) => {
          const width = (Math.abs(tc.attribution_score) / maxScore) * 100;
          const isPhishing = tc.direction === 'phishing';
          const featureName = tc.feature_name.replaceAll('_', ' ');
          const desc = FEATURE_DESCRIPTIONS[tc.feature_name];
          const indicator = indicatorMap.get(tc.feature_name);
          const isOpen = expanded === i;

          return (
            <div key={i}>
              <button
                onClick={() => setExpanded(isOpen ? null : i)}
                className="w-full flex items-center gap-3 px-5 py-4 hover:bg-[var(--color-phismail-surface)] transition-colors text-left overflow-hidden"
              >
                <span className="text-xs font-mono w-36 shrink-0 truncate text-[var(--color-phismail-text-muted)] capitalize">
                  {featureName}
                </span>
                <div className="flex-1 min-w-0 h-5 bg-[var(--color-phismail-surface)] rounded-lg overflow-hidden">
                  <div
                    className={`h-full rounded-lg transition-all duration-700 ${
                      isPhishing
                        ? 'bg-gradient-to-r from-red-500/30 to-red-500'
                        : 'bg-gradient-to-r from-green-500/30 to-green-500'
                    }`}
                    style={{ width: `${width}%` }}
                  />
                </div>
                <span
                  className={`text-xs font-bold w-12 text-right shrink-0 ${
                    isPhishing ? 'text-red-400' : 'text-green-400'
                  }`}
                >
                  {tc.attribution_score > 0 ? '+' : ''}
                  {tc.attribution_score.toFixed(1)}
                </span>
                <span className="text-[var(--color-phismail-text-dim)] text-xs w-4 shrink-0">
                  {isOpen ? '▲' : '▼'}
                </span>
              </button>

              {isOpen && (
                <div className={`px-5 pb-5 pt-2 text-sm space-y-4 border-l-2 ml-5 ${
                  isPhishing ? 'border-red-500/50' : 'border-green-500/50'
                }`}>

                  {/* File-specific finding */}
                  {indicator?.detail ? (
                    <div className={`rounded-lg p-3 ${
                      isPhishing ? 'bg-red-500/5 border border-red-500/20' : 'bg-green-500/5 border border-green-500/20'
                    }`}>
                      <span className="text-xs font-semibold uppercase tracking-wider text-[var(--color-phismail-text-muted)]">
                        🔍 Finding in this email
                      </span>
                      <p className={`mt-1.5 font-medium leading-relaxed break-words ${
                        isPhishing ? 'text-red-200' : 'text-green-200'
                      }`}>
                        {indicator.detail}
                      </p>
                    </div>
                  ) : desc ? (
                    <div className="rounded-lg p-3 bg-[var(--color-phismail-surface)]">
                      <span className="text-xs font-semibold uppercase tracking-wider text-[var(--color-phismail-text-muted)]">
                        {isPhishing ? '🔍 What was detected' : '✅ What this tells us'}
                      </span>
                      <p className="mt-1.5 text-[var(--color-phismail-text)] leading-relaxed">{desc.what}</p>
                    </div>
                  ) : null}

                  {/* Why it matters */}
                  {desc && (
                    <div>
                      <span className="text-xs font-semibold uppercase tracking-wider text-[var(--color-phismail-text-muted)]">
                        Why this matters
                      </span>
                      <p className="mt-1.5 text-[var(--color-phismail-text-muted)] leading-relaxed">{desc.why}</p>
                    </div>
                  )}

                  {/* Footer: severity badge + contribution score */}
                  <div className="flex items-center gap-2 pt-1 flex-wrap">
                    {indicator?.severity && (
                      <span className={`text-xs px-2 py-0.5 rounded font-semibold ${SEVERITY_STYLE[indicator.severity] ?? ''}`}>
                        {indicator.severity}
                      </span>
                    )}
                    <span className={`text-xs px-2 py-0.5 rounded font-semibold ${
                      isPhishing ? 'bg-red-500/10 text-red-400' : 'bg-green-500/10 text-green-400'
                    }`}>
                      {isPhishing ? '▲ Increases risk' : '▼ Reduces risk'}
                    </span>
                    <span className="text-xs text-[var(--color-phismail-text-dim)]">
                      Score contribution: {tc.attribution_score > 0 ? '+' : ''}{tc.attribution_score.toFixed(2)} pts
                    </span>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
