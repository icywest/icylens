import { useState } from 'react';
import type { StaticAnalysisResult } from '../lib/api';
import { AnalysisPipeline } from './AnalysisPipeline';
import { EntropyVisualization } from './EntropyVisualization';
import { MLPredictionVisualization } from './MLPredictionVisualization';
import { StaticFeatureVisualization } from './StaticFeatureVisualization';

type BrowserFileMetadata = { name: string; size: number; type: string };
type ResultPlaceholderProps = {
  result: StaticAnalysisResult;
  browserFile: BrowserFileMetadata;
  sourceFile: File;
};

export function ResultPlaceholder({
  result,
  browserFile,
  sourceFile,
}: ResultPlaceholderProps) {
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
    <div className="space-y-5" aria-label="Technical analysis results">
      <ResultSection title="File overview">
        <dl className="grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
          <ResultField label="Filename" value={result.filename} />
          <ResultField
            label="Analyzed size"
            value={formatBytes(fingerprint.size_bytes)}
          />
          <ResultField
            label="Detected format"
            value={formatDetectedFormat(fingerprint.detected_format)}
          />
          <ResultField
            label="Browser-declared MIME"
            value={browserFile.type || 'Not provided'}
          />
          <ResultField label="Filename extension" value={extension || 'None'} />
          <ResultField
            label="Extension consistency"
            value={formatConsistency(fingerprint.format_consistency)}
          />
          <ResultField
            label="Backend validation"
            value="Accepted and analyzed"
          />
          <ResultField label="Analysis type" value="Static" />
        </dl>
        <p className="text-xs leading-5 text-neutral-500">
          The MIME value is declared by the browser. Detected format is based on
          bounded backend signature inspection; neither proves that the complete
          file structure is valid.
        </p>
      </ResultSection>

      <ResultSection title="Fingerprints">
        <div className="space-y-2">
          <div className="text-xs text-neutral-500">SHA-256</div>
          <div className="flex flex-col gap-2 sm:flex-row sm:items-start">
            <code className="min-w-0 flex-1 break-all rounded border border-neutral-800 bg-neutral-950 p-2 text-xs text-neutral-300">
              {fingerprint.sha256}
            </code>
            <button
              type="button"
              onClick={copyHash}
              className="rounded border border-neutral-700 px-3 py-2 text-xs text-neutral-300 hover:bg-neutral-900 focus:outline-none focus-visible:ring-1 focus-visible:ring-neutral-400"
            >
              Copy hash
            </button>
          </div>
          <div aria-live="polite" className="min-h-4 text-xs text-neutral-500">
            {copyStatus === 'copied' && 'Hash copied.'}
            {copyStatus === 'error' && 'Copy failed. Select the hash manually.'}
          </div>
          <p className="text-xs leading-5 text-neutral-500">
            A cryptographic fingerprint calculated from the file contents. It
            does not determine whether a file is malicious.
          </p>
        </div>
      </ResultSection>

      <ResultSection title="Entropy">
        <EntropyVisualization
          value={content.entropy.shannon_entropy}
          totalBytes={content.entropy.total_bytes}
        />
      </ResultSection>

      <ResultSection title="Static features">
        <StaticFeatureVisualization
          strings={content.strings}
          indicators={result.indicators}
          indicatorsTruncated={result.indicators_truncated}
        />
      </ResultSection>

      <ResultSection title="How the analysis fits together">
        <AnalysisPipeline result={result} />
      </ResultSection>

      <ResultSection title="Machine-learning visualization">
        <MLPredictionVisualization file={sourceFile} />
      </ResultSection>

      <ResultSection title="Limitations">
        <ul className="list-disc space-y-2 pl-4 text-xs leading-5 text-neutral-500">
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
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-3 rounded-md border border-neutral-800 p-4">
      <h3 className="text-sm font-medium text-neutral-200">{title}</h3>
      {children}
    </section>
  );
}

function ResultField({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-neutral-500">{label}</dt>
      <dd className="break-words text-neutral-300">{value}</dd>
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
