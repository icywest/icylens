import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, type StaticAnalysisResult } from '../lib/api';
import { staticAnalysisFixture } from '../test/fixtures';
import { FileAnalysisApp } from './FileAnalysisApp';

const analyzeFileMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/api')>();
  return { ...actual, analyzeFile: analyzeFileMock };
});

describe('FileAnalysisApp', () => {
  beforeEach(() => {
    analyzeFileMock.mockReset();
  });

  it('analyzes only after explicit action and renders real response fields', async () => {
    const user = userEvent.setup();
    analyzeFileMock.mockResolvedValue(staticAnalysisFixture);
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    const { container } = render(<FileAnalysisApp />);
    const input = fileInput(container);
    const file = new File(['x'.repeat(64)], 'lesson.pdf', {
      type: 'application/octet-stream',
    });

    await user.upload(input, file);
    expect(analyzeFileMock).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Analyze File' }));

    expect(await screen.findByText('Analysis results')).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'File information' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Static analysis' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Analysis process' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Scientific limitations' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Choose another' }),
    ).toBeInTheDocument();
    expect(screen.getByText('PDF')).toBeInTheDocument();
    expect(screen.getByText('application/octet-stream')).toBeInTheDocument();
    expect(screen.getByText('a'.repeat(64))).toBeInTheDocument();
    expect(
      screen.getByRole('meter', { name: 'Shannon entropy' }),
    ).toHaveAttribute('aria-valuenow', '4.25');
    expect(
      screen.getByText(
        (_content, element) =>
          element?.tagName === 'LI' &&
          element.textContent?.includes('URL-like text was observed.') === true,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/does not determine whether a file is malicious/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        'Findings are descriptive and are not a malware verdict.',
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/malware detected|file is safe|threat confirmed/i),
    ).not.toBeInTheDocument();
    expect(setItem).not.toHaveBeenCalled();
    expect(analyzeFileMock).toHaveBeenCalledOnce();
  });

  it('cancels an active request and exposes the cancelled state', async () => {
    const user = userEvent.setup();
    analyzeFileMock.mockImplementation(
      (_file: File, options: { signal: AbortSignal }) =>
        new Promise((_resolve, reject) => {
          options.signal.addEventListener('abort', () => {
            reject(new ApiError('cancelled', 'cancelled'));
          });
        }),
    );
    const { container } = render(<FileAnalysisApp />);
    await user.upload(fileInput(container), sampleFile('first.bin'));
    await user.click(screen.getByRole('button', { name: 'Analyze File' }));
    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(screen.getByText(/Analysis cancelled/)).toBeInTheDocument();
    expect(screen.queryByText('Analysis results')).not.toBeInTheDocument();
    expect(
      (analyzeFileMock.mock.calls[0]?.[1] as { signal: AbortSignal }).signal
        .aborted,
    ).toBe(true);
  });

  it('invalidates stale responses when a file is replaced', async () => {
    const user = userEvent.setup();
    let resolveFirst!: (value: StaticAnalysisResult) => void;
    let resolveSecond!: (value: StaticAnalysisResult) => void;
    analyzeFileMock
      .mockImplementationOnce(
        () =>
          new Promise<StaticAnalysisResult>(
            (resolve) => (resolveFirst = resolve),
          ),
      )
      .mockImplementationOnce(
        () =>
          new Promise<StaticAnalysisResult>(
            (resolve) => (resolveSecond = resolve),
          ),
      );
    const { container } = render(<FileAnalysisApp />);
    const input = fileInput(container);

    await user.upload(input, sampleFile('first.bin'));
    await user.click(screen.getByRole('button', { name: 'Analyze File' }));
    await user.upload(input, sampleFile('second.bin'));
    expect(
      (analyzeFileMock.mock.calls[0]?.[1] as { signal: AbortSignal }).signal
        .aborted,
    ).toBe(true);
    await user.click(screen.getByRole('button', { name: 'Analyze File' }));

    const secondResult: StaticAnalysisResult = {
      ...staticAnalysisFixture,
      filename: 'second.bin',
      fingerprint: {
        ...staticAnalysisFixture.fingerprint,
        detected_format: 'png',
        format_consistency: 'mismatch',
      },
    };
    await act(async () => resolveSecond(secondResult));
    await waitFor(() => {
      expect(screen.getAllByText('second.bin')).toHaveLength(2);
    });
    await act(async () => resolveFirst(staticAnalysisFixture));
    await waitFor(() => {
      expect(screen.getAllByText('second.bin')).toHaveLength(2);
      expect(screen.queryByText('lesson.pdf')).not.toBeInTheDocument();
    });
  });

  it('shows a safe error and permits retry', async () => {
    const user = userEvent.setup();
    analyzeFileMock
      .mockRejectedValueOnce(
        new ApiError(
          'network',
          'The local analysis service could not be reached.',
        ),
      )
      .mockResolvedValueOnce(staticAnalysisFixture);
    const { container } = render(<FileAnalysisApp />);

    await user.upload(fileInput(container), sampleFile('lesson.pdf'));
    await user.click(screen.getByRole('button', { name: 'Analyze File' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The local analysis service could not be reached.',
    );

    await user.click(screen.getByRole('button', { name: 'Retry analysis' }));
    expect(await screen.findByText('Analysis results')).toBeInTheDocument();
    expect(analyzeFileMock).toHaveBeenCalledTimes(2);
  });
});

function fileInput(container: HTMLElement): HTMLInputElement {
  const input = container.querySelector('input[type="file"]');
  if (!(input instanceof HTMLInputElement))
    throw new Error('File input missing');
  return input;
}

function sampleFile(name: string): File {
  return new File(['x'.repeat(64)], name, { type: 'application/octet-stream' });
}
