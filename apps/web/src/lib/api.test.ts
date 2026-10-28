import { afterEach, describe, expect, it, vi } from 'vitest';
import { staticAnalysisFixture } from '../test/fixtures';
import {
  analyzeFile,
  analyzeFileWithML,
  ApiError,
  MAX_FILE_BYTES,
  staticAnalysisResultSchema,
} from './api';
import { mlInferenceFixture } from '../test/fixtures';

describe('analyzeFile', () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('posts the file once using the real multipart contract', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(jsonResponse(staticAnalysisFixture));
    vi.stubGlobal('fetch', fetchMock);
    const file = new File(['x'.repeat(64)], 'lesson.pdf', {
      type: 'application/pdf',
    });

    const result = await analyzeFile(file);

    expect(result.fingerprint.sha256).toBe('a'.repeat(64));
    expect(fetchMock).toHaveBeenCalledOnce();
    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe('/api/v1/static-analyses/');
    expect(init.method).toBe('POST');
    expect(init.headers).toBeUndefined();
    expect(init.body).toBeInstanceOf(FormData);
    expect((init.body as FormData).get('file')).toBeInstanceOf(File);
    expect(((init.body as FormData).get('file') as File).name).toBe(
      'lesson.pdf',
    );
  });

  it.each([
    [new File([], 'empty.bin'), 'empty'],
    [new File([new Uint8Array(MAX_FILE_BYTES + 1)], 'large.bin'), 'exceeds'],
  ])('rejects invalid local input before fetch', async (file, message) => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    await expect(analyzeFile(file)).rejects.toMatchObject({
      kind: 'validation',
      message: expect.stringContaining(message),
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    [{ ...staticAnalysisFixture, status: 'processing' }, 'incompatible'],
    [{ ...staticAnalysisFixture, response_version: '2' }, 'incompatible'],
    [
      {
        ...staticAnalysisFixture,
        fingerprint: {
          ...staticAnalysisFixture.fingerprint,
          sha256: 'invalid',
        },
      },
      'incompatible',
    ],
  ])('rejects response schema mismatches', async (payload, message) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(payload)));
    await expect(analyzeFile(sampleFile())).rejects.toMatchObject({
      kind: 'invalid-response',
      message: expect.stringContaining(message),
    });
  });

  it('rejects invalid JSON', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response('not-json', { status: 200 })),
    );
    await expect(analyzeFile(sampleFile())).rejects.toMatchObject({
      kind: 'invalid-response',
    });
  });

  it.each([
    [413, 'too large'],
    [422, 'file must not be empty'],
    [500, 'could not complete'],
  ])('sanitizes HTTP %s errors', async (status, message) => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse({ detail: 'file must not be empty' }, status),
        ),
    );
    await expect(analyzeFile(sampleFile())).rejects.toMatchObject({
      kind: 'http',
      status,
      message: expect.stringContaining(message),
    });
  });

  it('reports an unavailable backend as a network error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new TypeError('private detail')),
    );
    await expect(analyzeFile(sampleFile())).rejects.toEqual(
      new ApiError(
        'network',
        'The local analysis service could not be reached.',
      ),
    );
  });

  it('times out and aborts the underlying request', async () => {
    vi.useFakeTimers();
    const fetchMock = abortableFetch();
    vi.stubGlobal('fetch', fetchMock);

    const request = analyzeFile(sampleFile(), { timeoutMs: 10 });
    const rejection = expect(request).rejects.toMatchObject({
      kind: 'timeout',
    });
    await vi.advanceTimersByTimeAsync(10);

    await rejection;
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(init.signal?.aborted).toBe(true);
  });

  it('honors an external AbortSignal', async () => {
    const fetchMock = abortableFetch();
    vi.stubGlobal('fetch', fetchMock);
    const controller = new AbortController();

    const request = analyzeFile(sampleFile(), { signal: controller.signal });
    controller.abort();

    await expect(request).rejects.toMatchObject({ kind: 'cancelled' });
  });

  it('requires consistent byte counts and ordered timestamps', () => {
    expect(
      staticAnalysisResultSchema.safeParse({
        ...staticAnalysisFixture,
        completed_at: '2026-10-27T19:59:59Z',
        content: {
          ...staticAnalysisFixture.content,
          entropy: {
            ...staticAnalysisFixture.content.entropy,
            total_bytes: 63,
          },
        },
      }).success,
    ).toBe(false);
  });
});

describe('analyzeFileWithML', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('uses the file-linked ML endpoint and validates synthetic provenance', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(jsonResponse(mlInferenceFixture));
    vi.stubGlobal('fetch', fetchMock);
    const result = await analyzeFileWithML(sampleFile());
    expect(result.demo_only).toBe(true);
    expect(result.model.dataset_provenance_type).toBe('synthetic');
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/ml-inferences/');
    expect((fetchMock.mock.calls[0]?.[1] as RequestInit).body).toBeInstanceOf(
      FormData,
    );
  });

  it('reports the default disabled endpoint as unavailable', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse({ detail: 'ML inference is unavailable.' }, 503),
        ),
    );
    await expect(analyzeFileWithML(sampleFile())).rejects.toMatchObject({
      status: 503,
      message: 'The synthetic ML demonstration is unavailable.',
    });
  });

  it('rejects probabilities and provenance outside the backend contract', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse({
          ...mlInferenceFixture,
          prediction: {
            ...mlInferenceFixture.prediction,
            probability_estimates: { benign: 0.8, malicious: 0.8 },
          },
        }),
      ),
    );
    await expect(analyzeFileWithML(sampleFile())).rejects.toMatchObject({
      kind: 'invalid-response',
    });
  });
});

function sampleFile(): File {
  return new File(['x'.repeat(64)], 'lesson.pdf', { type: 'application/pdf' });
}

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function abortableFetch() {
  return vi.fn(
    (_input: RequestInfo | URL, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          reject(new DOMException('Aborted', 'AbortError'));
        });
      }),
  );
}
