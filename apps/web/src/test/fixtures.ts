import type { MLInferenceResult, StaticAnalysisResult } from '../lib/api';

export const staticAnalysisFixture: StaticAnalysisResult = {
  analysis_id: 'de305d54-75b4-431b-adb2-eb6b9e546014',
  analysis_type: 'static',
  status: 'completed',
  filename: 'lesson.pdf',
  created_at: '2026-10-27T20:00:00Z',
  completed_at: '2026-10-27T20:00:01Z',
  fingerprint: {
    sha256: 'a'.repeat(64),
    size_bytes: 64,
    detected_format: 'pdf',
    format_consistency: 'match',
  },
  content: {
    entropy: {
      shannon_entropy: 4.25,
      total_bytes: 64,
    },
    strings: {
      observed_count: 4,
      retained_count: 3,
      truncated: false,
      raw_strings_exposed: false,
      minimum_length: 4,
      maximum_retained_strings: 100,
      maximum_characters_per_string: 256,
    },
  },
  indicators: [
    {
      id: 'network.url_candidate',
      category: 'network',
      description: 'URL-like text was observed.',
      source: 'printable_ascii',
      offset: 12,
      evidence: 'https://example.test',
      severity: 'informational',
    },
  ],
  indicators_truncated: false,
  analysis_limitations: [
    {
      code: 'static_only',
      description: 'Analysis is limited to static inspection.',
    },
    {
      code: 'no_execution',
      description: 'Uploaded content was not executed.',
    },
    {
      code: 'no_malware_verdict',
      description: 'Findings are descriptive and are not a malware verdict.',
    },
  ],
};

export const mlInferenceFixture: MLInferenceResult = {
  inference_id: 'de305d54-75b4-431b-adb2-eb6b9e546015',
  analysis_id: 'de305d54-75b4-431b-adb2-eb6b9e546014',
  inference_mode: 'synthetic_demo',
  demo_only: true,
  status: 'completed',
  prediction: {
    label: 'malicious',
    probability_estimates: { benign: 0.4, malicious: 0.6 },
    probability_calibrated: false,
    interpretation: 'model_output_not_security_verdict',
  },
  model: {
    model_id: 'demo-logistic-v1',
    algorithm: 'logistic_regression',
    experiment_id: 'demo-experiment-v1',
    feature_schema_version: '1.0.0',
    dataset_id: 'synthetic-metadata-v1',
    dataset_integrity_digest: 'b'.repeat(64),
    dataset_provenance_type: 'synthetic',
    evaluation_status: 'synthetic_validation_only',
    model_selection_status: 'not_selected',
    lifecycle_status: 'registered_demo',
    operational_detection_approved: false,
  },
  limitations: [
    { code: 'synthetic_model_only', description: 'Synthetic model only.' },
    { code: 'not_security_verdict', description: 'Not a security verdict.' },
    {
      code: 'probability_not_calibrated',
      description: 'Probabilities are not calibrated.',
    },
    { code: 'static_analysis_only', description: 'Static analysis only.' },
    { code: 'bounded_analysis', description: 'Analysis bounds apply.' },
  ],
};
