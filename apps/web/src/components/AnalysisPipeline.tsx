import { useState } from 'react';
import type { StaticAnalysisResult } from '../lib/api';

export function AnalysisPipeline({ result }: { result: StaticAnalysisResult }) {
  const [openStage, setOpenStage] = useState<number | null>(null);
  const stages = buildStages(result);
  return (
    <div className="space-y-3">
      <p className="rounded border border-neutral-800 bg-neutral-950 p-3 text-xs leading-5 text-neutral-500">
        Conceptual model only. This is not an execution trace and does not show
        measured stage timing, backend events, or hidden processing state.
      </p>
      <ol className="pipeline-grid" aria-label="Conceptual analysis pipeline">
        {stages.map((stage, index) => {
          const expanded = openStage === index;
          const panelId = `pipeline-stage-${index}`;
          return (
            <li key={stage.name} className="pipeline-stage">
              <button
                type="button"
                className="pipeline-stage__button"
                aria-expanded={expanded}
                aria-controls={panelId}
                onClick={() => setOpenStage(expanded ? null : index)}
              >
                <span className="pipeline-stage__number">{index + 1}</span>
                <span>{stage.name}</span>
              </button>
              {expanded && (
                <div id={panelId} className="pipeline-stage__detail">
                  <p>{stage.description}</p>
                  <dl>
                    <dt>Result data</dt>
                    <dd>{stage.data}</dd>
                    <dt>Boundary</dt>
                    <dd>{stage.limitation}</dd>
                  </dl>
                </div>
              )}
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function buildStages(result: StaticAnalysisResult) {
  return [
    {
      name: 'Validation',
      description: 'The backend accepts a bounded, non-empty multipart upload.',
      data: `${result.fingerprint.size_bytes.toLocaleString('en-US')} bytes accepted`,
      limitation:
        'Acceptance does not establish safety or structural validity.',
    },
    {
      name: 'Identification',
      description: 'Leading bytes are compared with supported file signatures.',
      data: `Detected format: ${result.fingerprint.detected_format}; extension consistency: ${result.fingerprint.format_consistency}`,
      limitation:
        'Signature identification does not fully parse or validate the file.',
    },
    {
      name: 'Fingerprinting',
      description: 'SHA-256 identifies the exact accepted byte stream.',
      data: `SHA-256 ${result.fingerprint.sha256.slice(0, 12)}…`,
      limitation:
        'A hash is an identity value, not a maliciousness assessment.',
    },
    {
      name: 'Feature Extraction',
      description:
        'Bounded byte statistics and printable text runs are summarized.',
      data: `${result.content.strings.observed_count.toLocaleString('en-US')} strings observed; entropy ${result.content.entropy.shannon_entropy.toFixed(4)} bits/byte`,
      limitation:
        'Configured extraction bounds can omit additional observations.',
    },
    {
      name: 'Static Analysis',
      description:
        'Informational patterns are inspected without executing content.',
      data: `${result.indicators.length.toLocaleString('en-US')}${result.indicators_truncated ? '+' : ''} indicators retained`,
      limitation:
        'Static patterns may occur in benign files and are not behavior.',
    },
    {
      name: 'Interpretation',
      description:
        'Technical observations are presented with their limitations.',
      data: `${result.analysis_limitations.length.toLocaleString('en-US')} limitations disclosed`,
      limitation: 'No malware, clean-file, or security verdict is produced.',
    },
  ];
}
