"use client";

export default function Footer() {
  return (
    <footer
      className="relative z-10 mt-20"
      style={{ borderTop: "1px solid var(--pm-border)" }}
    >
      <div className="max-w-6xl mx-auto px-6 py-5 flex items-center justify-between">
        <span className="text-xs" style={{ color: "var(--pm-text-muted)" }}>
          &copy; {new Date().getFullYear()} PhisMail
        </span>
        <div className="flex items-center gap-4">
          <a
            href="https://github.com/srinivxs/phismail"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs transition-colors duration-150"
            style={{ color: "var(--pm-text-muted)" }}
            onMouseEnter={(e) => (e.currentTarget.style.color = "var(--pm-text-secondary)")}
            onMouseLeave={(e) => (e.currentTarget.style.color = "var(--pm-text-muted)")}
          >
            GitHub
          </a>
          <a
            href="https://www.linkedin.com/in/srinivas-vb"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs transition-colors duration-150"
            style={{ color: "var(--pm-text-muted)" }}
            onMouseEnter={(e) => (e.currentTarget.style.color = "var(--pm-text-secondary)")}
            onMouseLeave={(e) => (e.currentTarget.style.color = "var(--pm-text-muted)")}
          >
            Built by Srinivas V B
          </a>
        </div>
      </div>
    </footer>
  );
}
