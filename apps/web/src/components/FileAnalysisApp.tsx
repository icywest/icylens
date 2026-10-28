import { RotateCw, Square } from 'lucide-react';
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
      if (requestSequence.current === requestId)
        activeController.current = null;
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
  const completed =
    status === 'completed' && result !== null && selectedFile !== null;

  return (
    <div className="analysis-app">
      <section
        className="upload-workbench"
        data-compact={completed}
        aria-labelledby="upload-heading"
      >
        <div className="upload-workbench__header">
          <h2 id="upload-heading">Select a file</h2>
        </div>
        <div className="upload-workbench__body">
          <FileUploader
            onFileSelected={onFileSelected}
            maxBytes={MAX_FILE_BYTES}
            compact={completed}
          />
        </div>

        {selectedFile && !completed && (
          <div className="analysis-action">
            {status === 'analyzing' ? (
              <div
                className="processing-state"
                role="status"
                aria-live="polite"
              >
                <span
                  className="processing-state__indicator"
                  aria-hidden="true"
                />
                <div className="analysis-action__copy">
                  <strong>Analyzing file</strong>FastAPI is validating and
                  inspecting the uploaded bytes.
                </div>
              </div>
            ) : (
              <div className="analysis-action__copy">
                <strong>Ready for bounded static analysis</strong>No file
                content is executed by this workflow.
              </div>
            )}
            {status === 'analyzing' ? (
              <button type="button" onClick={cancel} className="button">
                <Square size={13} fill="currentColor" aria-hidden="true" />
                Cancel
              </button>
            ) : (
              <button
                type="button"
                onClick={analyze}
                disabled={!canAnalyze}
                className="button button--primary"
              >
                {status === 'error' && (
                  <RotateCw size={14} aria-hidden="true" />
                )}
                {status === 'error' ? 'Retry analysis' : 'Analyze File'}
              </button>
            )}
          </div>
        )}
      </section>

      {status === 'cancelled' && (
        <div role="status" aria-live="polite" className="technical-empty">
          Analysis cancelled. Cancelling the browser request may not stop
          backend processing immediately.
        </div>
      )}
      {status === 'error' && error && (
        <div role="alert" className="request-error">
          {error}
        </div>
      )}

      {completed && (
        <section aria-labelledby="results-heading">
          <div className="results-header">
            <div>
              <h2 id="results-heading">Analysis results</h2>
              <p className="results-header__status">
                Analysis completed successfully.
              </p>
            </div>
            <div className="flex flex-col items-end gap-2 max-sm:items-start">
              <div className="results-header__meta">{result.analysis_id}</div>
              <button
                type="button"
                onClick={analyze}
                className="button button--quiet"
              >
                <RotateCw size={13} aria-hidden="true" />
                Analyze again
              </button>
            </div>
          </div>
          <div className="mt-5">
            <ResultPlaceholder
              result={result}
              sourceFile={selectedFile}
              browserFile={{
                name: selectedFile.name,
                size: selectedFile.size,
                type: selectedFile.type,
              }}
            />
          </div>
        </section>
      )}
    </div>
  );
}
