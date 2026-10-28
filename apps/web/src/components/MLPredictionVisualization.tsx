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
    <div className="space-y-3">
      <div className="rounded border border-neutral-800 bg-neutral-950 p-3 text-xs leading-5 text-neutral-500">
        <p className="text-neutral-300">Synthetic educational demonstration</p>
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
          className="rounded border border-neutral-700 px-3 py-2 text-xs text-neutral-300 hover:bg-neutral-900 focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-300 disabled:opacity-50"
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
    <div className="space-y-4" aria-label="Synthetic ML result">
      <div className="feature-grid">
        <MLField label="Model output" value={result.prediction.label} />
        <MLField
          label="Benign estimate"
          value={`${(probabilities.benign * 100).toFixed(2)}%`}
        />
        <MLField
          label="Malicious estimate"
          value={`${(probabilities.malicious * 100).toFixed(2)}%`}
        />
      </div>
      <p className="text-xs leading-5 text-neutral-500">
        These are uncalibrated class probability estimates from model{' '}
        <code className="text-neutral-300">{result.model.model_id}</code>. They
        are not confidence, risk, or a security verdict. Operational detection
        approval: no.
      </p>
      <dl className="grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
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
      <ul className="list-disc space-y-1 pl-4 text-xs leading-5 text-neutral-500">
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
    <div className="min-w-0">
      <dt className="text-neutral-500">{label}</dt>
      <dd className="break-words text-neutral-300">{value}</dd>
    </div>
  );
}
