import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { staticAnalysisFixture } from '../test/fixtures';
import { AnalysisPipeline } from './AnalysisPipeline';

describe('AnalysisPipeline', () => {
  it('renders six keyboard-operable conceptual stages without fake timing', async () => {
    const user = userEvent.setup();
    render(<AnalysisPipeline result={staticAnalysisFixture} />);
    const buttons = screen.getAllByRole('button');
    expect(buttons).toHaveLength(6);
    expect(screen.getByText(/not an execution trace/i)).toBeInTheDocument();
    expect(
      screen.queryByText(/milliseconds|duration|started at/i),
    ).not.toBeInTheDocument();
    await user.tab();
    expect(buttons[0]).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(buttons[0]).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByText(/64 bytes accepted/i)).toBeInTheDocument();
  });

  it.each([
    'Validation',
    'Identification',
    'Fingerprinting',
    'Feature Extraction',
    'Static Analysis',
    'Interpretation',
  ])('includes the %s stage', (stage) => {
    render(<AnalysisPipeline result={staticAnalysisFixture} />);
    expect(
      screen.getByRole('button', { name: new RegExp(stage, 'i') }),
    ).toBeInTheDocument();
  });
});
