import { Check, Copy } from 'lucide-react';
import { useState } from 'react';
import type { StaticAnalysisResult } from '../lib/api';
import { AnalysisPipeline } from './AnalysisPipeline';
import { EntropyVisualization } from './EntropyVisualization';
import { MLPredictionVisualization } from './MLPredictionVisualization';
import { StaticFeatureVisualization } from './StaticFeatureVisualization';

type BrowserFileMetadata = { name: string; size: number; type: string };
type Props = {
  result: StaticAnalysisResult;
  browserFile: BrowserFileMetadata;
  sourceFile: File;
};

export function ResultPlaceholder({ result, browserFile, sourceFile }: Props) {
  const [copyStatus, setCopyStatus] = useState<'idle' | 'copied' | 'error'>(
    'idle',
  );
  const { fingerprint, content } = result;
  const extension = getExtension(browserFile.name);

  const copyHash = async () => {
    try {
      await navigator.clipboard.writeText(fingerprint.sha256);
      setCopyStatus('copied');
    } catch {
      setCopyStatus('error');
    }
  };

  return (
    <div className="results-stack" aria-label="Technical analysis results">
      <ResultSection
        title="File information"
        description="Identity and fingerprint of the accepted file."
      >
        <dl className="property-table">
          <Property label="Filename" value={result.filename} />
          <Property
            label="File size"
            value={formatBytes(fingerprint.size_bytes)}
          />
          <Property
            label="Detected format"
            value={formatDetectedFormat(fingerprint.detected_format)}
          />
          <Property
            label="Browser MIME"
            value={browserFile.type || 'Not provided'}
          />
          <Property label="Extension" value={extension || 'None'} />
          <Property
            label="Extension consistency"
            value={formatConsistency(fingerprint.format_consistency)}
          />
          <Property label="Validation status" value="Accepted and analyzed" />
          <Property label="Analysis type" value="Static" />
          <div className="property-row property-row--hash">
            <dt>SHA-256</dt>
            <dd>
              <div className="fingerprint__row">
                <code>{fingerprint.sha256}</code>
                <button
                  type="button"
                  onClick={copyHash}
                  className="button button--secondary"
                  aria-label="Copy hash"
                >
                  {copyStatus === 'copied' ? (
                    <Check size={14} aria-hidden="true" />
                  ) : (
                    <Copy size={14} aria-hidden="true" />
                  )}
                  {copyStatus === 'copied' ? 'Copied' : 'Copy hash'}
                </button>
              </div>
              <div aria-live="polite" className="copy-status">
                {copyStatus === 'copied' && 'Hash copied.'}
                {copyStatus === 'error' &&
                  'Copy failed. Select the hash manually.'}
              </div>
              <p className="help-text">
                A cryptographic fingerprint calculated from the file contents.
                It does not determine whether a file is malicious.
              </p>
            </dd>
          </div>
        </dl>
      </ResultSection>

      <ResultSection
        title="Static analysis"
        description="Bounded properties extracted without executing the file."
      >
        <div className="static-layout">
          <div className="static-layout__entropy">
            <EntropyVisualization
              value={content.entropy.shannon_entropy}
              totalBytes={content.entropy.total_bytes}
            />
          </div>
          <StaticFeatureVisualization
            strings={content.strings}
            indicators={result.indicators}
            indicatorsTruncated={result.indicators_truncated}
          />
        </div>
      </ResultSection>

      <ResultSection
        title="Analysis process"
        description="Conceptual stages used to organize the analysis."
      >
        <AnalysisPipeline result={result} />
      </ResultSection>

      <ResultSection
        className="result-section--secondary"
        title="Machine learning educational lab"
        description="Optional synthetic demonstration, separate from the file analysis result."
      >
        <MLPredictionVisualization file={sourceFile} />
      </ResultSection>

      <ResultSection
        title="Scientific limitations"
        description="These backend-provided boundaries apply to interpretation."
      >
        <ul className="limitation-list">
          {result.analysis_limitations.map((limitation) => (
            <li key={limitation.code}>{limitation.description}</li>
          ))}
        </ul>
      </ResultSection>
    </div>
  );
}

function ResultSection({
  title,
  description,
  className = '',
  children,
}: {
  title: string;
  description: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <section className={`result-section ${className}`}>
      <header className="result-section__header">
        <h3>{title}</h3>
        <p>{description}</p>
      </header>
      <div className="result-section__body">{children}</div>
    </section>
  );
}

function Property({ label, value }: { label: string; value: string }) {
  return (
    <div className="property-row">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function formatBytes(bytes: number): string {
  return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KiB`;
}
function getExtension(filename: string): string | null {
  const index = filename.lastIndexOf('.');
  return index <= 0 || index === filename.length - 1
    ? null
    : filename.slice(index + 1).toLowerCase();
}
function formatDetectedFormat(
  format: StaticAnalysisResult['fingerprint']['detected_format'],
): string {
  return format === 'unknown' ? 'Not determined' : format.toUpperCase();
}
function formatConsistency(
  consistency: StaticAnalysisResult['fingerprint']['format_consistency'],
): string {
  if (consistency === 'match') return 'Matches detected format';
  if (consistency === 'mismatch') return 'Does not match detected format';
  return 'Not determined';
}
