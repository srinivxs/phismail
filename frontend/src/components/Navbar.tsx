"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { useTheme } from "./ThemeProvider";

function UtcClock() {
  const [time, setTime] = useState("");

  useEffect(() => {
    const tick = () => {
      const now = new Date();
      const hh = String(now.getUTCHours()).padStart(2, "0");
      const mm = String(now.getUTCMinutes()).padStart(2, "0");
      const ss = String(now.getUTCSeconds()).padStart(2, "0");
      setTime(`${hh}:${mm}:${ss}`);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <span className="font-mono text-xs tabular-nums" style={{ color: "var(--color-phismail-text-muted)" }}>
      {time} UTC
    </span>
  );
}

function SunIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="5" />
      <line x1="12" y1="1" x2="12" y2="3" />
      <line x1="12" y1="21" x2="12" y2="23" />
      <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
      <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
      <line x1="1" y1="12" x2="3" y2="12" />
      <line x1="21" y1="12" x2="23" y2="12" />
      <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
      <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  );
}

const NAV_LINKS = [
  { href: "/", label: "dashboard", exact: true },
  { href: "/submit", label: "submit", exact: false },
];

export default function Navbar() {
  const path = usePathname();
  const { theme, toggle } = useTheme();

  return (
    <nav
      className="fixed top-0 left-0 right-0 z-50 border-b"
      style={{
        background:           "var(--color-phismail-nav-bg)",
        borderColor:          "var(--color-phismail-border)",
        backdropFilter:       "blur(20px)",
        WebkitBackdropFilter: "blur(20px)",
      }}
    >
      <div className="max-w-7xl mx-auto px-6 h-14 flex items-center justify-between gap-6">

        {/* ── Logo ── */}
        <Link href="/" className="flex items-center gap-2.5 shrink-0">
          <span className="text-base font-bold tracking-tight font-mono" style={{ letterSpacing: "-0.01em" }}>
            <span style={{ color: "var(--color-phismail-purple)" }}>Phis</span>
            <span style={{ color: "var(--color-phismail-text)" }}>Mail</span>
          </span>
          <span
            className="hidden sm:inline-flex text-[10px] px-1.5 py-0.5 rounded font-mono"
            style={{
              color:      "var(--color-phismail-text-muted)",
              border:     "1px solid var(--color-phismail-border)",
              background: "var(--color-phismail-surface)",
            }}
          >
            v0.1
          </span>
        </Link>

        {/* ── Nav links — monospace terminal style ── */}
        <div className="flex items-center gap-1">
          {NAV_LINKS.map(({ href, label, exact }) => {
            const active = exact ? path === href : path.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                className="relative px-4 py-1.5 rounded text-sm font-mono font-medium transition-all duration-200"
                style={{
                  color:      active ? "var(--color-phismail-purple)" : "var(--color-phismail-text-muted)",
                  background: active ? "var(--color-phismail-purple-glow)" : "transparent",
                  border:     active ? "1px solid var(--color-phismail-border)" : "1px solid transparent",
                }}
              >
                {active && (
                  <span style={{ color: "var(--color-phismail-green)" }}>›</span>
                )}{" "}
                {label}
              </Link>
            );
          })}
        </div>

        {/* ── Right side ── */}
        <div className="flex items-center gap-3 shrink-0">

          {/* UTC Clock */}
          <div className="hidden md:flex items-center gap-1.5">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: "var(--color-phismail-text-muted)" }}>
              <circle cx="12" cy="12" r="10" />
              <polyline points="12,6 12,12 16,14" />
            </svg>
            <UtcClock />
          </div>

          {/* System status */}
          <div
            className="hidden md:flex items-center gap-1.5 text-xs font-mono"
            style={{ color: "var(--color-phismail-text-muted)" }}
          >
            <span
              className="w-1.5 h-1.5 rounded-full animate-pulse"
              style={{ background: "var(--color-phismail-green)" }}
            />
            ONLINE
          </div>

          {/* Divider */}
          <div
            className="hidden md:block w-px h-4"
            style={{ background: "var(--color-phismail-border)" }}
          />

          {/* Theme toggle */}
          <button
            onClick={toggle}
            title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
            className="w-8 h-8 rounded flex items-center justify-center transition-all duration-200"
            style={{
              background:  "var(--color-phismail-surface)",
              border:      "1px solid var(--color-phismail-border)",
              color:       "var(--color-phismail-text-muted)",
            }}
          >
            {theme === "dark" ? <SunIcon /> : <MoonIcon />}
          </button>
        </div>
      </div>
    </nav>
  );
}
