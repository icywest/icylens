import { z } from 'zod';

export const MAX_FILE_BYTES = 10 * 1024 * 1024;
export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
export const API_BASE_URL = (import.meta.env.PUBLIC_API_BASE_URL ?? '').replace(
  /\/+$/,
  '',
);

const detectedFormatSchema = z.enum([
  'pdf',
  'png',
  'jpeg',
  'gif',
  'zip',
  'pe',
  'elf',
  'unknown',
]);
const formatConsistencySchema = z.enum(['match', 'mismatch', 'unknown']);
const utcTimestampSchema = z
  .string()
  .refine(
    (value) => !Number.isNaN(Date.parse(value)) && /(Z|\+00:00)$/.test(value),
    { message: 'Expected a UTC timestamp' },
  );

const fingerprintSchema = z
  .object({
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
    size_bytes: z.number().int().positive(),
    detected_format: detectedFormatSchema,
    format_consistency: formatConsistencySchema,
  })
  .strict();
const entropySchema = z
  .object({
    shannon_entropy: z.number().min(0).max(8),
    total_bytes: z.number().int().positive(),
  })
  .strict();
const stringsSchema = z
  .object({
    observed_count: z.number().int().nonnegative(),
    retained_count: z.number().int().nonnegative(),
    truncated: z.boolean(),
    raw_strings_exposed: z.literal(false),
    minimum_length: z.number().int().positive(),
    maximum_retained_strings: z.number().int().positive(),
    maximum_characters_per_string: z.number().int().positive(),
  })
  .strict();
const indicatorSchema = z
  .object({
    id: z.string(),
    category: z.enum(['network', 'command', 'file']),
    description: z.string(),
    source: z.literal('printable_ascii'),
    offset: z.number().int().nonnegative().nullable(),
    evidence: z.string().max(96).nullable(),
    severity: z.literal('informational'),
  })
  .strict();
const limitationSchema = z
  .object({
    code: z.enum([
      'static_only',
      'no_execution',
      'no_malware_verdict',
      'format_not_validity',
      'entropy_not_maliciousness',
      'text_indicators_may_be_benign',
      'configured_bounds_apply',
    ]),
    description: z.string(),
  })
  .strict();

export const staticAnalysisResultSchema = z
  .object({
    analysis_id: z.uuid(),
    analysis_type: z.literal('static'),
    status: z.literal('completed'),
    filename: z.string().min(1).max(255),
    created_at: utcTimestampSchema,
    completed_at: utcTimestampSchema,
    fingerprint: fingerprintSchema,
    content: z
      .object({ entropy: entropySchema, strings: stringsSchema })
      .strict(),
    indicators: z.array(indicatorSchema),
    indicators_truncated: z.boolean(),
    analysis_limitations: z.array(limitationSchema),
  })
  .strict()
  .superRefine((result, context) => {
    if (result.fingerprint.size_bytes !== result.content.entropy.total_bytes) {
      context.addIssue({
        code: 'custom',
        message: 'Byte counts do not describe the same input',
        path: ['content', 'entropy', 'total_bytes'],
      });
    }
    if (Date.parse(result.completed_at) < Date.parse(result.created_at)) {
      context.addIssue({
        code: 'custom',
        message: 'Completion precedes creation',
        path: ['completed_at'],
      });
    }
  });

export type StaticAnalysisResult = z.infer<typeof staticAnalysisResultSchema>;

const mlLimitationCodeSchema = z.enum([
  'synthetic_model_only',
  'not_security_verdict',
  'probability_not_calibrated',
  'static_analysis_only',
  'bounded_analysis',
]);

export const mlInferenceResultSchema = z
  .object({
    inference_id: z.uuid(),
    analysis_id: z.uuid(),
    inference_mode: z.literal('synthetic_demo'),
    demo_only: z.literal(true),
    status: z.literal('completed'),
    prediction: z
      .object({
        label: z.enum(['benign', 'malicious']),
        probability_estimates: z
          .object({
            benign: z.number().min(0).max(1),
            malicious: z.number().min(0).max(1),
          })
          .strict(),
        probability_calibrated: z.literal(false),
        interpretation: z.literal('model_output_not_security_verdict'),
      })
      .strict(),
    model: z
      .object({
        model_id: z.string().min(1),
        algorithm: z.enum([
          'logistic_regression',
          'random_forest',
          'hist_gradient_boosting',
        ]),
        experiment_id: z.string().min(1),
        feature_schema_version: z.literal('1.0.0'),
        dataset_id: z.string().min(1),
        dataset_integrity_digest: z.string().regex(/^[0-9a-f]{64}$/),
        dataset_provenance_type: z.literal('synthetic'),
        evaluation_status: z.literal('synthetic_validation_only'),
        model_selection_status: z.literal('not_selected'),
        lifecycle_status: z.literal('registered_demo'),
        operational_detection_approved: z.literal(false),
      })
      .strict(),
    limitations: z.array(
      z
        .object({
          code: mlLimitationCodeSchema,
          description: z.string().min(1),
        })
        .strict(),
    ),
  })
  .strict()
  .superRefine((result, context) => {
    const probabilities = result.prediction.probability_estimates;
    if (Math.abs(probabilities.benign + probabilities.malicious - 1) > 1e-9) {
      context.addIssue({
        code: 'custom',
        message: 'ML probabilities do not sum to one',
        path: ['prediction', 'probability_estimates'],
      });
    }
    if (new Set(result.limitations.map((item) => item.code)).size !== 5) {
      context.addIssue({
        code: 'custom',
        message: 'ML response does not disclose every required limitation',
        path: ['limitations'],
      });
    }
  });

export type MLInferenceResult = z.infer<typeof mlInferenceResultSchema>;
export type ApiErrorKind =
  | 'validation'
  | 'http'
  | 'network'
  | 'timeout'
  | 'cancelled'
  | 'invalid-response';

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status?: number;

  constructor(kind: ApiErrorKind, message: string, status?: number) {
    super(message);
    this.name = 'ApiError';
    this.kind = kind;
    this.status = status;
  }
}

type AnalyzeFileOptions = { signal?: AbortSignal; timeoutMs?: number };

export async function analyzeFile(
  file: File,
  options: AnalyzeFileOptions = {},
): Promise<StaticAnalysisResult> {
  if (file.size === 0) {
    throw new ApiError('validation', 'The selected file is empty.');
  }
  if (file.size > MAX_FILE_BYTES) {
    throw new ApiError(
      'validation',
      `The selected file exceeds the ${formatMiB(MAX_FILE_BYTES)} limit.`,
    );
  }

  const form = new FormData();
  form.append('file', file, file.name);
  const payload = await requestJson('/api/v1/static-analyses/', {
    method: 'POST',
    body: form,
    signal: options.signal,
    timeoutMs: options.timeoutMs,
  });
  const parsed = staticAnalysisResultSchema.safeParse(payload);
  if (!parsed.success) {
    throw new ApiError(
      'invalid-response',
      'The analysis service returned an incompatible response.',
    );
  }
  return parsed.data;
}

export async function analyzeFileWithML(
  file: File,
  options: AnalyzeFileOptions = {},
): Promise<MLInferenceResult> {
  if (file.size === 0 || file.size > MAX_FILE_BYTES) {
    throw new ApiError(
      'validation',
      file.size === 0
        ? 'The selected file is empty.'
        : `The selected file exceeds the ${formatMiB(MAX_FILE_BYTES)} limit.`,
    );
  }
  const form = new FormData();
  form.append('file', file, file.name);
  const payload = await requestJson('/api/v1/ml-inferences/', {
    method: 'POST',
    body: form,
    signal: options.signal,
    timeoutMs: options.timeoutMs,
  });
  const parsed = mlInferenceResultSchema.safeParse(payload);
  if (!parsed.success) {
    throw new ApiError(
      'invalid-response',
      'The ML service returned an incompatible response.',
    );
  }
  return parsed.data;
}

export type MLDemoOutcome =
  | { status: 'complete'; result: MLInferenceResult }
  | { status: 'unavailable'; message: string };

export async function requestMLDemo(
  file: File,
  options: AnalyzeFileOptions = {},
): Promise<MLDemoOutcome> {
  try {
    return {
      status: 'complete',
      result: await analyzeFileWithML(file, options),
    };
  } catch (error) {
    if (error instanceof ApiError && error.status === 503) {
      return { status: 'unavailable', message: error.message };
    }
    throw error;
  }
}

type RequestOptions = RequestInit & { timeoutMs?: number };

async function requestJson(
  path: string,
  options: RequestOptions,
): Promise<unknown> {
  const controller = new AbortController();
  const externalSignal = options.signal;
  let timedOut = false;
  const abortFromExternal = () => controller.abort(externalSignal?.reason);

  if (externalSignal?.aborted) abortFromExternal();
  else
    externalSignal?.addEventListener('abort', abortFromExternal, {
      once: true,
    });

  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, options.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS);

  try {
    const { timeoutMs: _timeoutMs, ...requestOptions } = options;
    void _timeoutMs;
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...requestOptions,
      signal: controller.signal,
    });
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      if (!response.ok) throw httpError(response.status);
      throw new ApiError(
        'invalid-response',
        'The analysis service returned invalid JSON.',
      );
    }
    if (!response.ok) throw httpError(response.status, safeDetail(payload));
    return payload;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (controller.signal.aborted) {
      if (timedOut)
        throw new ApiError('timeout', 'The analysis request timed out.');
      throw new ApiError('cancelled', 'The analysis request was cancelled.');
    }
    throw new ApiError(
      'network',
      'The local analysis service could not be reached.',
    );
  } finally {
    clearTimeout(timeout);
    externalSignal?.removeEventListener('abort', abortFromExternal);
  }
}

function safeDetail(payload: unknown): string | undefined {
  if (
    typeof payload === 'object' &&
    payload !== null &&
    'detail' in payload &&
    typeof payload.detail === 'string' &&
    payload.detail.length <= 200
  ) {
    return payload.detail;
  }
  return undefined;
}

function httpError(status: number, detail?: string): ApiError {
  if (status === 413) {
    return new ApiError(
      'http',
      'The backend rejected the file as too large.',
      status,
    );
  }
  if (status === 422) {
    return new ApiError(
      'http',
      detail ?? 'The backend rejected the file.',
      status,
    );
  }
  if (status === 404) {
    return new ApiError(
      'http',
      'The configured analysis endpoint was not found.',
      status,
    );
  }
  if (status === 503) {
    return new ApiError(
      'http',
      'The synthetic ML demonstration is unavailable.',
      status,
    );
  }
  if (status === 429) {
    return new ApiError(
      'http',
      'The synthetic ML demonstration is at capacity. Try again later.',
      status,
    );
  }
  return new ApiError(
    'http',
    'The analysis service could not complete the request.',
    status,
  );
}

function formatMiB(bytes: number): string {
  return `${bytes / (1024 * 1024)} MiB`;
}
