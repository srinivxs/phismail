"use client";

/* ============================================================
   PhisMail — 9-Stage Analysis Pipeline Architecture View
   Each card explains one forensic stage in SOC/CTI terminology.
   ============================================================ */

interface PipelineStep {
  step: number;
  phase: string;
  phaseColor: string;
  title: string;
  subtitle: string;
  description: string;
  tags: string[];
  icon: React.ReactNode;
}

function IconShield() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="M9 12l2 2 4-4" strokeWidth="2"/>
    </svg>
  );
}
function IconCode() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="16,18 22,12 16,6"/>
      <polyline points="8,6 2,12 8,18"/>
    </svg>
  );
}
function IconAuth() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <polyline points="9,12 11,14 15,10" strokeWidth="2"/>
    </svg>
  );
}
function IconLink() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
      <line x1="18" y1="6" x2="22" y2="2" strokeWidth="2" stroke="#f43f5e"/>
    </svg>
  );
}
function IconGlobe() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <line x1="2" y1="12" x2="22" y2="12"/>
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
    </svg>
  );
}
function IconHub() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3"/>
      <circle cx="12" cy="3"  r="2"/>
      <circle cx="21" cy="12" r="2"/>
      <circle cx="12" cy="21" r="2"/>
      <circle cx="3"  cy="12" r="2"/>
      <line x1="12" y1="5"  x2="12" y2="9"/>
      <line x1="19" y1="12" x2="15" y2="12"/>
      <line x1="12" y1="15" x2="12" y2="19"/>
      <line x1="5"  y1="12" x2="9"  y2="12"/>
    </svg>
  );
}
function IconScan() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8"/>
      <line x1="21" y1="21" x2="16.65" y2="16.65"/>
      <path d="M8 11h6M11 8v6" strokeWidth="1.5"/>
    </svg>
  );
}
function IconChart() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="20" x2="18" y2="10"/>
      <line x1="12" y1="20" x2="12" y2="4"/>
      <line x1="6"  y1="20" x2="6"  y2="14"/>
      <line x1="2"  y1="20" x2="22" y2="20"/>
    </svg>
  );
}
function IconReport() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
      <polyline points="14,2 14,8 20,8"/>
      <line x1="9" y1="13" x2="15" y2="13"/>
      <line x1="9" y1="17" x2="15" y2="17"/>
      <polyline points="9,9 10,9 12,11"/>
    </svg>
  );
}

const STEPS: PipelineStep[] = [
  {
    step: 1,
    phase: "INGESTION",
    phaseColor: "#0070f3",
    title: "Artifact Intake",
    subtitle: "Secure artifact ingestion & triage",
    description:
      "Raw email (.eml) or suspicious URL is sanitized, SHA-256 fingerprinted for deduplication, and written to the secure artifact vault. A Celery task is enqueued via Redis broker. The analyst never touches the raw threat directly.",
    tags: ["RFC 5322", "SHA-256", "Redis Broker", "Artifact Vault"],
    icon: <IconShield />,
  },
  {
    step: 2,
    phase: "STATIC ANALYSIS",
    phaseColor: "#fb923c",
    title: "Header Forensics",
    subtitle: "Deep RFC 5322/MIME parsing",
    description:
      "Full MIME structure decomposition extracts sender envelope, received-chain hops, MIME boundaries, and every X- header. Routing metadata reveals the true origin IP, SMTP relay path, and number of infrastructure hops.",
    tags: ["MIME Parsing", "Hop Extraction", "Envelope Analysis", "X-Headers"],
    icon: <IconCode />,
  },
  {
    step: 3,
    phase: "STATIC ANALYSIS",
    phaseColor: "#fb923c",
    title: "Authentication Verification",
    subtitle: "SPF · DKIM · DMARC chain validation",
    description:
      "SPF validates the sending MTA IP against the domain's DNS policy. DKIM cryptographically verifies the message signature to confirm integrity in transit. DMARC enforces alignment; all three must pass to establish sender legitimacy.",
    tags: ["SPF Alignment", "DKIM Signature", "DMARC Policy", "Spoofing Detection"],
    icon: <IconAuth />,
  },
  {
    step: 4,
    phase: "DYNAMIC ANALYSIS",
    phaseColor: "#a78bfa",
    title: "URL Threat Surface",
    subtitle: "Structural analysis & live redirect tracing",
    description:
      "Every extracted URL undergoes entropy scoring, obfuscation pattern detection (percent encoding, IP literals, username-in-URL), and live HTTP crawling to trace the full redirect chain to the final landing page.",
    tags: ["URL Entropy", "Redirect Tracing", "IP Literal Detection", "Domain Obfuscation"],
    icon: <IconLink />,
  },
  {
    step: 5,
    phase: "DYNAMIC ANALYSIS",
    phaseColor: "#a78bfa",
    title: "OSINT Domain Profiling",
    subtitle: "WHOIS · DNS · typosquat detection",
    description:
      "WHOIS enrichment captures registrar, registration date, and domain age. Full DNS enumeration covers MX, TXT, SPF, and DMARC records. Homograph detection and Levenshtein-based typosquat scoring expose lookalike domains impersonating trusted brands.",
    tags: ["WHOIS Lookup", "DNS Enumeration", "Homograph Attack", "Typosquatting"],
    icon: <IconGlobe />,
  },
  {
    step: 6,
    phase: "DYNAMIC ANALYSIS",
    phaseColor: "#a78bfa",
    title: "Multi-Feed IOC Correlation",
    subtitle: "Concurrent threat intelligence queries",
    description:
      "Async concurrent queries hit OpenPhish (real-time phishing feed), PhishTank (community-verified database), and URLhaus (malware distribution feed) simultaneously. Domain and IP are cross-referenced against all three. A hit from any feed is an immediate high-confidence indicator.",
    tags: ["OpenPhish", "PhishTank", "URLhaus", "IOC Matching", "Threat Intel"],
    icon: <IconHub />,
  },
  {
    step: 7,
    phase: "CONTENT ANALYSIS",
    phaseColor: "#f43f5e",
    title: "Social Engineering NLP",
    subtitle: "Adversarial language pattern detection",
    description:
      "Keyword-pattern engine identifies the four social engineering pillars: urgency (act now/immediately), credential harvesting (verify your account/enter password), financial manipulation (wire transfer/invoice overdue), and security impersonation (account suspended/unusual activity). Content-only scores are capped to prevent NLP-only verdicts.",
    tags: ["Urgency Language", "Credential Harvesting", "Phishing Psychology", "NLP Scoring"],
    icon: <IconScan />,
  },
  {
    step: 8,
    phase: "SCORING",
    phaseColor: "#4ade80",
    title: "Adversarial Risk Scoring",
    subtitle: "Dual-bucket suspicion / trust engine",
    description:
      "~80 features across 12 dimensions feed a dual-bucket engine: raw_risk = suspicion_score − trust_score. Trust signals (DKIM pass, ESP detected, bulk mail headers, CDN domains) reduce the score, preventing false positives on legitimate marketing email. SHAP-compatible feature attribution produces the top-10 risk contributors.",
    tags: ["Dual-Bucket Scoring", "SHAP Attribution", "80+ Features", "False Positive Reduction"],
    icon: <IconChart />,
  },
  {
    step: 9,
    phase: "REPORTING",
    phaseColor: "#4ade80",
    title: "Intelligence Report",
    subtitle: "Verdict assignment · IOC export · STIX2",
    description:
      "Final verdict assigned across four tiers: SAFE (<20), MARKETING (20–50), SUSPICIOUS (50–75), PHISHING (≥75). Full investigation report includes all indicators with human-readable findings, domain intelligence, redirect chains, and top risk contributors. IOCs exported in STIX2, JSON, or CSV for SIEM ingestion.",
    tags: ["SAFE/MARKETING/SUSPICIOUS/PHISHING", "STIX2 Export", "IOC Extraction", "SIEM Ingestion"],
    icon: <IconReport />,
  },
];

export default function PipelineView() {
  return (
    <section>
      {/* Section header */}
      <div className="mb-6">
        <div className="flex items-center gap-2 mb-1">
          <span className="font-mono text-sm font-bold" style={{ color: "var(--color-phismail-purple)" }}>&lt;</span>
          <h2 className="font-mono text-sm font-bold" style={{ color: "var(--color-phismail-text)" }}>pipeline_architecture</h2>
          <span className="font-mono text-sm font-bold" style={{ color: "var(--color-phismail-green)" }}>/&gt;</span>
        </div>
        <p className="font-mono text-xs" style={{ color: "var(--color-phismail-text-muted)" }}>
          // 9-stage forensic engine · artifact intake → structured threat intelligence
        </p>
      </div>

      {/* Pipeline grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {STEPS.map((s) => (
          <div
            key={s.step}
            className="glass-panel p-5 flex flex-col gap-3 animate-fade-in-up"
            style={{
              borderLeft: `3px solid ${s.phaseColor}`,
              animationDelay: `${(s.step - 1) * 55}ms`,
            }}
          >
            {/* Top row: icon + step number */}
            <div className="flex items-start justify-between">
              <div
                className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
                style={{
                  background: `${s.phaseColor}18`,
                  color: s.phaseColor,
                  border: `1px solid ${s.phaseColor}30`,
                }}
              >
                {s.icon}
              </div>
              <div className="text-right">
                <div
                  className="text-[10px] font-bold uppercase tracking-widest"
                  style={{ color: s.phaseColor }}
                >
                  {s.phase}
                </div>
                <div
                  className="font-mono text-xs mt-0.5"
                  style={{ color: "var(--color-phismail-text-muted)" }}
                >
                  STEP {String(s.step).padStart(2, "0")}
                </div>
              </div>
            </div>

            {/* Title + subtitle */}
            <div>
              <h3
                className="font-bold text-sm leading-snug"
                style={{ color: "var(--color-phismail-text)" }}
              >
                {s.title}
              </h3>
              <p
                className="text-xs mt-0.5"
                style={{ color: s.phaseColor, opacity: 0.85 }}
              >
                {s.subtitle}
              </p>
            </div>

            {/* Description */}
            <p
              className="text-xs leading-relaxed flex-1"
              style={{ color: "var(--color-phismail-text-muted)" }}
            >
              {s.description}
            </p>

            {/* Tags */}
            <div className="flex flex-wrap gap-1.5 pt-1">
              {s.tags.map((tag) => (
                <span
                  key={tag}
                  className="text-[10px] px-2 py-0.5 rounded font-medium"
                  style={{
                    background: `${s.phaseColor}10`,
                    color: s.phaseColor,
                    border: `1px solid ${s.phaseColor}22`,
                  }}
                >
                  {tag}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
