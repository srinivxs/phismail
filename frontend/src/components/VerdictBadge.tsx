"use client";

interface VerdictBadgeProps {
  verdict: 'SAFE' | 'MARKETING' | 'SUSPICIOUS' | 'PHISHING';
  size?: 'sm' | 'md' | 'lg';
}

const sizeClasses = {
  sm: 'text-sm font-semibold',
  md: 'text-xl font-bold',
  lg: 'text-4xl font-extrabold',
};

const verdictConfig = {
  SAFE: {
    icon: '✅',
    className: 'verdict-safe',
  },
  MARKETING: {
    icon: '📧',
    className: 'text-[var(--color-phismail-purple-light)]',
  },
  SUSPICIOUS: {
    icon: '⚠️',
    className: 'verdict-suspicious',
  },
  PHISHING: {
    icon: '🚨',
    className: 'text-[var(--color-severity-critical)]',
  },
};

export default function VerdictBadge({ verdict, size = 'md' }: VerdictBadgeProps) {
  const config = verdictConfig[verdict];
  return (
    <span className={`${config.className} ${sizeClasses[size]}`}>
      {config.icon} {verdict}
    </span>
  );
}
