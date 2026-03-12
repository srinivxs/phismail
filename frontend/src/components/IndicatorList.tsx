"use client";

import type { Indicator } from '@/lib/api';

interface IndicatorListProps {
  indicators: Indicator[];
}

const severityOrder: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
};

export default function IndicatorList({ indicators }: IndicatorListProps) {
  const sorted = [...indicators].sort(
    (a, b) => (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99)
  );

  return (
    <section>
      {sorted.length === 0 ? (
        <div className="glass-panel px-6 py-8 text-center text-[var(--color-phismail-text-muted)]">
          <span className="text-2xl">✅</span>
          <p className="mt-2">No indicators detected</p>
        </div>
      ) : (
        <div className="glass-panel divide-y divide-[var(--color-phismail-border)]">
          {sorted.map((ind, i) => (
            <div key={i} className="px-6 py-4 flex items-start gap-4">
              <span className={`badge badge-${ind.severity.toLowerCase()} mt-0.5 shrink-0`}>{ind.severity}</span>
              <div className="flex-1 min-w-0">
                <p className="font-semibold text-sm capitalize">{ind.indicator_type.replaceAll('_', ' ')}</p>
                {ind.detail && (
                  <p className="text-xs mt-1 leading-relaxed break-words" style={{ color: "var(--color-phismail-text-muted)" }}>
                    {ind.detail}
                  </p>
                )}
              </div>
              {ind.confidence !== undefined && ind.confidence !== null && (
                <span className="text-xs shrink-0 mt-0.5" style={{ color: "var(--color-phismail-text-dim)" }}>
                  {(ind.confidence * 100).toFixed(0)}%
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
