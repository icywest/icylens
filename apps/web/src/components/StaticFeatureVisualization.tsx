import type { StaticAnalysisResult } from '../lib/api';

type StaticFeatureVisualizationProps = {
  strings: StaticAnalysisResult['content']['strings'];
  indicators: StaticAnalysisResult['indicators'];
  indicatorsTruncated: boolean;
};

export function StaticFeatureVisualization({
  strings,
  indicators,
  indicatorsTruncated,
}: StaticFeatureVisualizationProps) {
  const retainedCapacity = Math.min(
    100,
    (strings.retained_count / strings.maximum_retained_strings) * 100,
  );

  return (
    <div className="space-y-4">
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
      <div className="space-y-2">
        <div className="flex justify-between gap-3 text-xs">
          <span className="text-neutral-400">Retained string capacity</span>
          <span className="text-neutral-500">
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
        <p className="text-xs text-neutral-600">
          This bar compares retained summaries with the configured backend cap;
          it does not represent severity.
        </p>
      </div>
      <div className="flex flex-wrap gap-2 text-xs">
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
        <ul
          className="space-y-2 text-xs text-neutral-500"
          aria-label="Indicators"
        >
          {indicators.map((indicator, index) => (
            <li
              key={`${indicator.id}-${index}`}
              className="rounded border border-neutral-800 p-2"
            >
              <span className="text-neutral-300">{indicator.category}</span>
              {' — '}
              {indicator.description}
            </li>
          ))}
        </ul>
      )}
      <p className="text-xs leading-5 text-neutral-600">
        Counts are bounded observations. Indicators are informational patterns
        that can also occur in benign files.
      </p>
    </div>
  );
}

function FeatureCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="feature-card">
      <div className="text-xl text-neutral-100">
        {value.toLocaleString('en-US')}
      </div>
      <div className="text-xs leading-5 text-neutral-500">{label}</div>
    </div>
  );
}

function BoundTag({ active, text }: { active: boolean; text: string }) {
  return (
    <span className="rounded border border-neutral-800 px-2 py-1 text-neutral-500">
      <span aria-hidden="true">{active ? '↳' : '✓'} </span>
      {text}
    </span>
  );
}
