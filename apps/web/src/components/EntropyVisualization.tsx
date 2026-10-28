type EntropyVisualizationProps = {
  value: number | null;
  totalBytes?: number | null;
};

export function EntropyVisualization({
  value,
  totalBytes,
}: EntropyVisualizationProps) {
  const valid =
    value !== null && Number.isFinite(value) && value >= 0 && value <= 8;

  if (!valid) {
    return (
      <div className="technical-empty" role="status">
        Entropy is unavailable for this analysis.
      </div>
    );
  }

  const percentage = (value / 8) * 100;

  return (
    <div className="space-y-3">
      <div className="flex items-baseline justify-between gap-3">
        <div>
          <span className="text-2xl font-medium text-neutral-100">
            {value.toFixed(4)}
          </span>{' '}
          <span className="text-xs text-neutral-500">bits/byte</span>
        </div>
        <span className="text-xs text-neutral-500">range 0–8</span>
      </div>
      <div
        className="entropy-scale"
        role="meter"
        aria-label="Shannon entropy"
        aria-valuemin={0}
        aria-valuemax={8}
        aria-valuenow={value}
        aria-valuetext={`${value.toFixed(4)} bits per byte out of 8`}
      >
        <div
          className="entropy-scale__value"
          style={{ width: `${percentage}%` }}
        />
      </div>
      <div className="flex justify-between text-[0.68rem] text-neutral-600">
        <span>0</span>
        <span>2</span>
        <span>4</span>
        <span>6</span>
        <span>8 bits/byte</span>
      </div>
      <p className="text-xs leading-5 text-neutral-500">
        Shannon entropy describes byte distribution
        {typeof totalBytes === 'number'
          ? ` across ${totalBytes.toLocaleString('en-US')} measured bytes`
          : ''}
        . It is not a risk score, threshold, or malware verdict.
      </p>
    </div>
  );
}
