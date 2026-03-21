"use client";

export default function Footer() {
  return (
    <footer
      className="relative z-10 mt-24 border-t"
      style={{ borderColor: "var(--color-phismail-border)" }}
    >
      <div className="max-w-7xl mx-auto px-6 py-10">

        {/* Top row: identity + linkedin */}
        <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-8">

          {/* Identity block */}
          <div className="space-y-2 max-w-md">
            <div className="flex items-center gap-1.5">
              <span className="font-mono text-base font-bold" style={{ color: "var(--color-phismail-purple)" }}>[</span>
              <span className="font-mono text-base font-bold" style={{ color: "var(--color-phismail-text)" }}>Srinivas V B</span>
              <span className="font-mono text-base font-bold" style={{ color: "var(--color-phismail-green)" }}>]</span>
            </div>
            <p className="text-xs leading-relaxed" style={{ color: "var(--color-phismail-text-muted)" }}>
              Security engineer and developer building phishing detection systems,
              threat intelligence pipelines, and SOC-grade analysis tooling.
            </p>
          </div>

          {/* LinkedIn */}
          <div className="space-y-2">
            <p className="font-mono text-[10px] uppercase tracking-widest font-semibold" style={{ color: "var(--color-phismail-text-muted)" }}>
              // connect
            </p>
            <a
              href="https://www.linkedin.com/in/srinivas-vb"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 font-mono text-xs transition-colors duration-150"
              style={{ color: "var(--color-phismail-text-muted)" }}
              onMouseEnter={(e) => (e.currentTarget.style.color = "var(--color-phismail-green)")}
              onMouseLeave={(e) => (e.currentTarget.style.color = "var(--color-phismail-text-muted)")}
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor">
                <path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z"/>
                <rect x="2" y="9" width="4" height="12"/>
                <circle cx="4" cy="4" r="2"/>
              </svg>
              linkedin.com/in/srinivas-vb
            </a>
          </div>
        </div>

        {/* Divider */}
        <div className="my-6 h-px" style={{ background: "var(--color-phismail-border)" }} />

        {/* Bottom row: contact + copyright */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">

          {/* Contact */}
          <div className="flex flex-wrap items-center gap-4">
            <a
              href="mailto:srinivasbalajee0063@gmail.com"
              className="font-mono text-xs transition-colors duration-150"
              style={{ color: "var(--color-phismail-text-muted)" }}
              onMouseEnter={(e) => (e.currentTarget.style.color = "var(--color-phismail-purple)")}
              onMouseLeave={(e) => (e.currentTarget.style.color = "var(--color-phismail-text-muted)")}
            >
              srinivasbalajee0063@gmail.com
            </a>
            <span className="font-mono text-xs" style={{ color: "var(--color-phismail-border)" }}>|</span>
            <span className="font-mono text-xs" style={{ color: "var(--color-phismail-text-muted)" }}>Chennai, India</span>
          </div>

          {/* Copyright */}
          <div className="space-y-0.5 text-right">
            <p className="font-mono text-[10px]" style={{ color: "var(--color-phismail-text-muted)" }}>
              &copy; 2026 Srinivas V B. All rights reserved.
            </p>
            <p className="font-mono text-[10px]" style={{ color: "var(--color-phismail-green)", opacity: 0.6 }}>
              // built with precision. secured by design.
            </p>
          </div>
        </div>

      </div>
    </footer>
  );
}
