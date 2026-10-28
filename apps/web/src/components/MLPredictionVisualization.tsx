import { useEffect, useRef, useState } from 'react';
import { ApiError, requestMLDemo, type MLInferenceResult } from '../lib/api';

export function MLPredictionVisualization({ file }: { file: File }) {
  const [status, setStatus] = useState<
    'idle' | 'loading' | 'complete' | 'unavailable' | 'error'
  >('idle');
  const [result, setResult] = useState<MLInferenceResult | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const controller = useRef<AbortController | null>(null);

  useEffect(() => () => controller.current?.abort(), []);

  const run = () => {
    controller.current?.abort();
    const nextController = new AbortController();
    controller.current = nextController;
    setStatus('loading');
    setResult(null);
    setMessage(null);
    void requestMLDemo(file, {
      signal: nextController.signal,
    }).then(
      (outcome) => {
        if (nextController.signal.aborted) return;
        if (outcome.status === 'unavailable') {
          setStatus('unavailable');
          setMessage(outcome.message);
        } else {
          setResult(outcome.result);
          setStatus('complete');
        }
      },
      (caught: unknown) => {
        if (nextController.signal.aborted) return;
        setStatus('error');
        setMessage(
          isApiError(caught)
            ? caught.message
            : 'The synthetic ML demonstration could not be completed.',
        );
      },
    );
  };

  return (
    <div className="grid gap-4">
      <div className="ml-intro">
        <strong>Synthetic educational demonstration</strong>
        <p>
          This optional action uploads the file to a separate,
          disabled-by-default endpoint. Its model was trained only on synthetic
          metadata.
        </p>
      </div>
      {status !== 'complete' && (
        <button
          type="button"
          onClick={run}
          disabled={status === 'loading'}
          className="button"
        >
          {status === 'loading'
            ? 'Running synthetic demo…'
            : 'Run synthetic ML demo'}
        </button>
      )}
      {message && (
        <div
          role={status === 'error' ? 'alert' : 'status'}
          className="technical-empty"
        >
          {message}
        </div>
      )}
      {result && <MLResult result={result} />}
    </div>
  );
}

function MLResult({ result }: { result: MLInferenceResult }) {
  const probabilities = result.prediction.probability_estimates;
  return (
    <div className="ml-result" aria-label="Synthetic ML result">
      <dl className="feature-grid">
        <MLField label="Model output" value={result.prediction.label} />
        <MLField
          label="Benign estimate"
          value={`${(probabilities.benign * 100).toFixed(2)}%`}
        />
        <MLField
          label="Malicious estimate"
          value={`${(probabilities.malicious * 100).toFixed(2)}%`}
        />
      </dl>
      <p className="ml-result__copy">
        These are uncalibrated class probability estimates from model{' '}
        <code>{result.model.model_id}</code>. They are not confidence, risk, or
        a security verdict. Operational detection approval: no.
      </p>
      <dl className="ml-detail-grid">
        <MLField label="Algorithm" value={result.model.algorithm} />
        <MLField
          label="Feature schema"
          value={result.model.feature_schema_version}
        />
        <MLField
          label="Dataset provenance"
          value={result.model.dataset_provenance_type}
        />
        <MLField
          label="Model selection"
          value={result.model.model_selection_status}
        />
      </dl>
      <ul className="ml-limitations">
        {result.limitations.map((item) => (
          <li key={item.code}>{item.description}</li>
        ))}
      </ul>
    </div>
  );
}

function isApiError(error: unknown): error is ApiError {
  return (
    error instanceof ApiError ||
    (typeof error === 'object' &&
      error !== null &&
      'message' in error &&
      typeof error.message === 'string' &&
      'status' in error &&
      typeof error.status === 'number')
  );
}

function MLField({ label, value }: { label: string; value: string }) {
  return (
    <div className="ml-field">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}
