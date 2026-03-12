"use client";

interface RiskGaugeProps {
  score: number;
  verdict: 'SAFE' | 'MARKETING' | 'SUSPICIOUS' | 'PHISHING';
  size?: number;
}

const verdictColor = {
  SAFE: '#22c55e',
  MARKETING: '#a855f7',
  SUSPICIOUS: '#eab308',
  PHISHING: '#ef4444',
};

export default function RiskGauge({ score, verdict, size = 160 }: RiskGaugeProps) {
  const radius = 45;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = verdictColor[verdict];

  return (
    <div className="relative flex-shrink-0" style={{ width: size, height: size }}>
      <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="none"
          stroke="var(--color-phismail-surface)"
          strokeWidth="8"
        />
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{
            animation: 'fillGauge 1.5s ease-out forwards',
            filter: `drop-shadow(0 0 8px ${color}40)`,
          }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-extrabold">{Math.round(score)}</span>
        <span className="text-xs text-[var(--color-phismail-text-muted)]">/100</span>
      </div>
    </div>
  );
}
