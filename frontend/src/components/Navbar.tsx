"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTheme } from "./ThemeProvider";
import { useAuth } from "./AuthProvider";

const NAV_LINKS = [
  { href: "/", label: "Dashboard", exact: true },
  { href: "/submit", label: "Analyze", exact: false },
];

export default function Navbar() {
  const path = usePathname();
  const { theme, toggle } = useTheme();
  const { user, logout, loading: authLoading } = useAuth();

  return (
    <nav
      className="fixed top-0 left-0 right-0 z-50 border-b"
      style={{
        background: "var(--pm-nav-bg)",
        borderColor: "var(--pm-border)",
        backdropFilter: "blur(12px)",
        WebkitBackdropFilter: "blur(12px)",
      }}
    >
      <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
        {/* Logo */}
        <Link href="/" className="flex items-center gap-2 shrink-0">
          <div
            className="w-7 h-7 rounded-lg flex items-center justify-center text-xs font-bold"
            style={{ background: "var(--pm-accent)", color: "#fff" }}
          >
            P
          </div>
          <span className="text-sm font-semibold" style={{ color: "var(--pm-text)" }}>
            PhisMail
          </span>
        </Link>

        {/* Nav links */}
        <div className="flex items-center gap-1">
          {NAV_LINKS.map(({ href, label, exact }) => {
            const active = exact ? path === href : path.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                className="px-3 py-1.5 rounded-md text-sm font-medium transition-colors duration-150"
                style={{
                  color: active ? "var(--pm-text)" : "var(--pm-text-secondary)",
                  background: active ? "var(--pm-surface-hover)" : "transparent",
                }}
              >
                {label}
              </Link>
            );
          })}
        </div>

        {/* Right side: theme toggle + auth */}
        <div className="flex items-center gap-2">
          <button
            onClick={toggle}
            title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
            className="w-8 h-8 rounded-md flex items-center justify-center transition-colors duration-150"
            style={{
              background: "transparent",
              border: "1px solid var(--pm-border)",
              color: "var(--pm-text-secondary)",
            }}
          >
            {theme === "dark" ? (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="5" />
                <line x1="12" y1="1" x2="12" y2="3" /><line x1="12" y1="21" x2="12" y2="23" />
                <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" /><line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
                <line x1="1" y1="12" x2="3" y2="12" /><line x1="21" y1="12" x2="23" y2="12" />
                <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" /><line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
              </svg>
            ) : (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
              </svg>
            )}
          </button>

          {!authLoading && (
            user ? (
              <div className="flex items-center gap-2">
                <div
                  className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-medium overflow-hidden"
                  style={{
                    background: "var(--pm-accent-muted)",
                    color: "var(--pm-accent)",
                    border: "1px solid var(--pm-border)",
                  }}
                >
                  {user.avatar_url ? (
                    <img src={user.avatar_url} alt="" className="w-full h-full object-cover" />
                  ) : (
                    (user.display_name || user.email)[0].toUpperCase()
                  )}
                </div>
                <button
                  onClick={logout}
                  className="text-xs font-medium transition-colors"
                  style={{ color: "var(--pm-text-muted)" }}
                  onMouseEnter={(e) => (e.currentTarget.style.color = "var(--pm-text-secondary)")}
                  onMouseLeave={(e) => (e.currentTarget.style.color = "var(--pm-text-muted)")}
                >
                  Sign out
                </button>
              </div>
            ) : (
              <Link
                href="/login"
                className="text-xs font-medium px-3 py-1.5 rounded-md transition-colors"
                style={{
                  color: "var(--pm-accent)",
                  background: "var(--pm-accent-muted)",
                }}
              >
                Sign in
              </Link>
            )
          )}
        </div>
      </div>
    </nav>
  );
}
