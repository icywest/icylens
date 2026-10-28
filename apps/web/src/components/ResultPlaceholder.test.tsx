import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { staticAnalysisFixture } from '../test/fixtures';
import { ResultPlaceholder } from './ResultPlaceholder';

describe('ResultPlaceholder', () => {
  it('renders unknown and absent browser metadata without inventing values', () => {
    render(
      <ResultPlaceholder
        result={{
          ...staticAnalysisFixture,
          filename: 'sample',
          fingerprint: {
            ...staticAnalysisFixture.fingerprint,
            detected_format: 'unknown',
            format_consistency: 'unknown',
          },
          indicators: [],
        }}
        sourceFile={new File(['x'], 'sample')}
        browserFile={{ name: 'sample', size: 64, type: '' }}
      />,
    );

    expect(screen.getAllByText('Not determined')).toHaveLength(2);
    expect(screen.getByText('Not provided')).toBeInTheDocument();
    expect(screen.getByText('None')).toBeInTheDocument();
    expect(
      screen.getByText(/No informational text-pattern indicators/),
    ).toBeInTheDocument();
  });

  it('copies the real SHA-256 value', async () => {
    const user = userEvent.setup();
    render(
      <ResultPlaceholder
        result={staticAnalysisFixture}
        sourceFile={new File(['x'], 'lesson.pdf')}
        browserFile={{ name: 'lesson.pdf', size: 64, type: 'application/pdf' }}
      />,
    );
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');

    await user.click(screen.getByRole('button', { name: 'Copy hash' }));

    expect(writeText).toHaveBeenCalledWith('a'.repeat(64));
    expect(screen.getByText('Hash copied.')).toBeInTheDocument();
  });

  it('labels ML as a separate synthetic action and renders no prediction before request', () => {
    render(
      <ResultPlaceholder
        result={staticAnalysisFixture}
        sourceFile={new File(['x'], 'lesson.pdf')}
        browserFile={{ name: 'lesson.pdf', size: 64, type: 'application/pdf' }}
      />,
    );
    expect(
      screen.getByText('Synthetic educational demonstration'),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Run synthetic ML demo' }),
    ).toBeInTheDocument();
    expect(screen.queryByText(/feature importance/i)).not.toBeInTheDocument();
    expect(
      screen.queryByText(/benign probability|malicious probability/i),
    ).not.toBeInTheDocument();
  });

  it('renders a long filename without replacing the backend value', () => {
    const filename = `${'long-'.repeat(40)}sample.pdf`;
    render(
      <ResultPlaceholder
        result={{ ...staticAnalysisFixture, filename }}
        sourceFile={new File(['x'], filename)}
        browserFile={{ name: filename, size: 64, type: '' }}
      />,
    );
    expect(screen.getByText(filename)).toBeInTheDocument();
  });
});
