"use client";

import type { DomainIntel } from '@/lib/api';

interface DomainIntelCardProps {
  domain: DomainIntel;
}

export default function DomainIntelCard({ domain: d }: DomainIntelCardProps) {
  return (
    <div className="glass-panel p-5 space-y-3">
      <h3 className="font-bold text-[var(--color-phismail-purple-light)]">{d.domain}</h3>
      <div className="space-y-1 text-sm">
        {d.registrar && (
          <p>
            <span className="text-[var(--color-phismail-text-muted)]">Registrar:</span> {d.registrar}
          </p>
        )}
        {d.domain_age_days !== undefined && d.domain_age_days !== null && (
          <p>
            <span className="text-[var(--color-phismail-text-muted)]">Age:</span>{' '}
            {d.domain_age_days < 30 ? (
              <span className="text-[var(--color-severity-critical)] font-bold">
                ⚠️ {d.domain_age_days} days - NEWLY REGISTERED
              </span>
            ) : (
              <span>{d.domain_age_days} days</span>
            )}
          </p>
        )}
        {d.nameservers && d.nameservers.length > 0 && (
          <p>
            <span className="text-[var(--color-phismail-text-muted)]">Nameservers:</span>{' '}
            {d.nameservers.length}
          </p>
        )}
        {d.tld_risk_score !== undefined && d.tld_risk_score !== null && d.tld_risk_score > 0.5 && (
          <p>
            <span className="text-[var(--color-phismail-text-muted)]">TLD Risk:</span>{' '}
            <span className="text-[var(--color-severity-high)] font-semibold">
              {(d.tld_risk_score * 100).toFixed(0)}%
            </span>
          </p>
        )}
        <div className="flex flex-wrap gap-2 pt-1">
          {d.is_homograph && <span className="badge badge-critical">Homograph</span>}
          {d.brand_impersonation && (
            <span className="badge badge-high">Brand Impersonation: {d.brand_keyword}</span>
          )}
        </div>
      </div>
    </div>
  );
}
