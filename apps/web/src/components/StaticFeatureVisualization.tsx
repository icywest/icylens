import type { StaticAnalysisResult } from '../lib/api';

type Props = {
  strings: StaticAnalysisResult['content']['strings'];
  indicators: StaticAnalysisResult['indicators'];
  indicatorsTruncated: boolean;
};

export function StaticFeatureVisualization({
  strings,
  indicators,
  indicatorsTruncated,
}: Props) {
  const retainedCapacity = Math.min(
    100,
    (strings.retained_count / strings.maximum_retained_strings) * 100,
  );
  return (
    <div className="grid gap-4">
      <div className="feature-grid">
        <FeatureCard
          label="Printable strings observed"
          value={strings.observed_count}
        />
        <FeatureCard
          label="String summaries retained"
          value={strings.retained_count}
        />
        <FeatureCard
          label="Informational indicators"
          value={indicators.length}
        />
      </div>
      <div className="grid gap-2">
        <div className="flex justify-between gap-3">
          <span className="technical-label">Retained string capacity</span>
          <span className="font-mono text-[.72rem] text-[var(--color-text-muted)]">
            {strings.retained_count.toLocaleString('en-US')} /{' '}
            {strings.maximum_retained_strings.toLocaleString('en-US')}
          </span>
        </div>
        <div
          className="capacity-scale"
          role="meter"
          aria-label="Retained string capacity"
          aria-valuemin={0}
          aria-valuemax={strings.maximum_retained_strings}
          aria-valuenow={strings.retained_count}
        >
          <div
            className="capacity-scale__value"
            style={{ width: `${retainedCapacity}%` }}
          />
        </div>
        <p className="explanation">
          This bar compares retained summaries with the configured backend cap;
          it does not represent severity.
        </p>
      </div>
      <div className="bound-tags">
        <BoundTag
          active={strings.truncated}
          text={
            strings.truncated ? 'Strings truncated' : 'Strings within bounds'
          }
        />
        <BoundTag
          active={indicatorsTruncated}
          text={
            indicatorsTruncated
              ? 'Indicators truncated'
              : 'Indicators within bounds'
          }
        />
      </div>
      {indicators.length === 0 ? (
        <div className="technical-empty">
          No informational text-pattern indicators were retained.
        </div>
      ) : (
        <ul className="indicator-list" aria-label="Indicators">
          {indicators.map((indicator, index) => (
            <li key={`${indicator.id}-${index}`} className="indicator-item">
              <strong>{indicator.category}</strong>
              {' — '}
              {indicator.description}
            </li>
          ))}
        </ul>
      )}
      <p className="explanation">
        Counts are bounded observations. Indicators are informational patterns
        that can also occur in benign files.
      </p>
    </div>
  );
}

function FeatureCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="feature-card">
      <div className="feature-card__value">{value.toLocaleString('en-US')}</div>
      <div className="feature-card__label">{label}</div>
    </div>
  );
}

function BoundTag({ active, text }: { active: boolean; text: string }) {
  return (
    <span className="bound-tag">
      <span aria-hidden="true">{active ? '↳' : '✓'} </span>
      {text}
    </span>
  );
}
