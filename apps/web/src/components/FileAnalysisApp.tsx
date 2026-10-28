import { useCallback, useEffect, useRef, useState } from 'react';
import {
  analyzeFile,
  ApiError,
  MAX_FILE_BYTES,
  type StaticAnalysisResult,
} from '../lib/api';
import { FileUploader } from './FileUploader';
import { ResultPlaceholder } from './ResultPlaceholder';

type AnalysisStatus =
  'idle' | 'selected' | 'analyzing' | 'completed' | 'error' | 'cancelled';

export function FileAnalysisApp() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [status, setStatus] = useState<AnalysisStatus>('idle');
  const [result, setResult] = useState<StaticAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const requestSequence = useRef(0);
  const activeController = useRef<AbortController | null>(null);

  const invalidateRequest = useCallback(() => {
    requestSequence.current += 1;
    activeController.current?.abort();
    activeController.current = null;
  }, []);

  useEffect(
    () => () => {
      requestSequence.current += 1;
      activeController.current?.abort();
    },
    [],
  );

  const onFileSelected = useCallback(
    (file: File | null) => {
      invalidateRequest();
      setResult(null);
      setError(null);
      setSelectedFile(file);
      setStatus(file ? 'selected' : 'idle');
    },
    [invalidateRequest],
  );

  const analyze = useCallback(async () => {
    if (!selectedFile || status === 'analyzing') return;

    const controller = new AbortController();
    const requestId = ++requestSequence.current;
    activeController.current = controller;
    setStatus('analyzing');
    setResult(null);
    setError(null);

    try {
      const nextResult = await analyzeFile(selectedFile, {
        signal: controller.signal,
      });
      if (requestSequence.current !== requestId) return;
      setResult(nextResult);
      setStatus('completed');
    } catch (caught) {
      if (requestSequence.current !== requestId) return;
      if (caught instanceof ApiError && caught.kind === 'cancelled') {
        setStatus('cancelled');
        return;
      }
      setError(
        caught instanceof ApiError
          ? caught.message
          : 'The analysis could not be completed.',
      );
      setStatus('error');
    } finally {
      if (requestSequence.current === requestId) {
        activeController.current = null;
      }
    }
  }, [selectedFile, status]);

  const cancel = useCallback(() => {
    if (status !== 'analyzing') return;
    requestSequence.current += 1;
    activeController.current?.abort();
    activeController.current = null;
    setResult(null);
    setError(null);
    setStatus('cancelled');
  }, [status]);

  const canAnalyze =
    selectedFile !== null &&
    selectedFile.size > 0 &&
    selectedFile.size <= MAX_FILE_BYTES &&
    status !== 'analyzing';

  return (
    <div className="space-y-6">
      <section className="space-y-3" aria-labelledby="upload-heading">
        <h2 id="upload-heading" className="text-sm text-neutral-300">
          Upload
        </h2>
        <FileUploader
          onFileSelected={onFileSelected}
          maxBytes={MAX_FILE_BYTES}
        />
      </section>

      {selectedFile && status !== 'analyzing' && status !== 'completed' && (
        <section className="flex flex-col gap-3 rounded-md border border-neutral-800 p-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="text-xs text-neutral-500">
            Ready for local FastAPI static analysis.
          </div>
          <button
            type="button"
            onClick={analyze}
            disabled={!canAnalyze}
            className="rounded border border-neutral-700 px-3 py-2 text-sm text-neutral-200 hover:bg-neutral-900 focus:outline-none focus-visible:ring-1 focus-visible:ring-neutral-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {status === 'error' ? 'Retry analysis' : 'Analyze File'}
          </button>
        </section>
      )}

      {status === 'analyzing' && (
        <section className="flex flex-col gap-3 rounded-md border border-neutral-800 p-4 sm:flex-row sm:items-center sm:justify-between">
          <div role="status" aria-live="polite" className="space-y-1">
            <div className="text-sm text-neutral-200">Analyzing file…</div>
            <div className="text-xs text-neutral-500">
              FastAPI is validating and inspecting the uploaded bytes.
            </div>
          </div>
          <button
            type="button"
            onClick={cancel}
            className="rounded border border-neutral-700 px-3 py-2 text-xs text-neutral-300 hover:bg-neutral-900 focus:outline-none focus-visible:ring-1 focus-visible:ring-neutral-400"
          >
            Cancel
          </button>
        </section>
      )}

      {status === 'cancelled' && (
        <div
          role="status"
          aria-live="polite"
          className="text-xs text-neutral-500"
        >
          Analysis cancelled. Cancelling the browser request may not stop
          backend processing immediately.
        </div>
      )}

      {status === 'error' && error && (
        <div
          role="alert"
          className="rounded-md border border-red-950 p-3 text-xs text-red-300"
        >
          {error}
        </div>
      )}

      {status === 'completed' && result && selectedFile && (
        <section className="space-y-3" aria-labelledby="results-heading">
          <div className="flex items-center justify-between gap-3">
            <h2 id="results-heading" className="text-sm text-neutral-300">
              Technical results
            </h2>
            <button
              type="button"
              onClick={analyze}
              className="rounded border border-neutral-800 px-3 py-1 text-xs text-neutral-400 hover:bg-neutral-900 focus:outline-none focus-visible:ring-1 focus-visible:ring-neutral-400"
            >
              Analyze again
            </button>
          </div>
          <ResultPlaceholder
            result={result}
            sourceFile={selectedFile}
            browserFile={{
              name: selectedFile.name,
              size: selectedFile.size,
              type: selectedFile.type,
            }}
          />
        </section>
      )}
    </div>
  );
}
