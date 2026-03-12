"use client";

interface RedirectChainViewProps {
  url: string;
  redirectChain: string[];
  finalDestination?: string;
  redirectCount: number;
}

const MAX_HOPS = 10;

export default function RedirectChainView({
  url,
  redirectChain,
  finalDestination,
  redirectCount,
}: RedirectChainViewProps) {
  if (redirectCount === 0) {
    return (
      <div className="mt-2 text-xs text-[var(--color-phismail-text-muted)]">
        ✅ No redirects detected
      </div>
    );
  }

  const displayChain = redirectChain.slice(0, MAX_HOPS);
  const truncated = redirectChain.length > MAX_HOPS ? redirectChain.length - MAX_HOPS : 0;
  const lastInChain = redirectChain[redirectChain.length - 1];
  const showFinalDiff =
    finalDestination && lastInChain && finalDestination !== lastInChain;

  return (
    <div className="mt-2 text-xs text-[var(--color-phismail-text-dim)] space-y-1">
      <p className="font-semibold text-[var(--color-phismail-text-muted)]">Redirect chain:</p>
      <div className="font-mono break-all">{url}</div>
      {displayChain.map((hop, j) => (
        <div key={j} className="flex items-start gap-2">
          <span className="text-[var(--color-phismail-purple)] shrink-0">→</span>
          <span className="font-mono break-all">{hop}</span>
        </div>
      ))}
      {truncated > 0 && (
        <p className="text-[var(--color-phismail-text-dim)] italic">
          ... and {truncated} more
        </p>
      )}
      {showFinalDiff && (
        <div className="flex items-start gap-2">
          <span className="text-[var(--color-severity-critical)] shrink-0 font-bold">Final:</span>
          <span className="font-mono break-all text-[var(--color-severity-critical)]">
            {finalDestination}
          </span>
        </div>
      )}
    </div>
  );
}
