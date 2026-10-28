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
  if (!valid)
    return (
      <div className="technical-empty" role="status">
        Entropy is unavailable for this analysis.
      </div>
    );
  const percentage = (value / 8) * 100;
  return (
    <div className="grid gap-3">
      <div className="flex items-end justify-between gap-3">
        <div className="entropy-value">
          <strong>{value.toFixed(4)}</strong>
          <span>bits / byte</span>
        </div>
        <span className="technical-label">Range 0–8</span>
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
      <div className="scale-labels">
        <span>0</span>
        <span>2</span>
        <span>4</span>
        <span>6</span>
        <span>8 bits/byte</span>
      </div>
      <p className="explanation">
        Measures uncertainty in the distribution of byte values
        {typeof totalBytes === 'number'
          ? ` across ${totalBytes.toLocaleString('en-US')} measured bytes`
          : ''}
        . It is not a risk score and cannot establish encryption, compression,
        or maliciousness by itself.
      </p>
    </div>
  );
}
