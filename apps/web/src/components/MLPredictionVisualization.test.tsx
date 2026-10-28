import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { mlInferenceFixture } from '../test/fixtures';
import { MLPredictionVisualization } from './MLPredictionVisualization';

const mlMock = vi.hoisted(() => vi.fn());
vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  requestMLDemo: mlMock,
}));

describe('MLPredictionVisualization', () => {
  beforeEach(() => mlMock.mockReset());

  it('runs only on explicit action and labels authentic output as synthetic and uncalibrated', async () => {
    mlMock.mockResolvedValue({
      status: 'complete',
      result: mlInferenceFixture,
    });
    const user = userEvent.setup();
    render(<MLPredictionVisualization file={new File(['x'], 'sample.bin')} />);
    expect(mlMock).not.toHaveBeenCalled();
    await user.click(
      screen.getByRole('button', { name: 'Run synthetic ML demo' }),
    );
    expect(
      await screen.findByLabelText('Synthetic ML result'),
    ).toBeInTheDocument();
    expect(screen.getByText('60.00%')).toBeInTheDocument();
    expect(
      screen.getByText(/uncalibrated class probability estimates/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Operational detection approval: no/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/feature importance/i)).not.toBeInTheDocument();
    expect(
      screen.queryByText(/threat detected|file is safe/i),
    ).not.toBeInTheDocument();
  });

  it('shows a clear unavailable state for the default backend configuration', async () => {
    mlMock.mockResolvedValue({
      status: 'unavailable',
      message: 'The synthetic ML demonstration is unavailable.',
    });
    const user = userEvent.setup();
    render(<MLPredictionVisualization file={new File(['x'], 'sample.bin')} />);
    await user.click(
      screen.getByRole('button', { name: 'Run synthetic ML demo' }),
    );
    expect(await screen.findByRole('status')).toHaveTextContent('unavailable');
    expect(
      screen.queryByLabelText('Synthetic ML result'),
    ).not.toBeInTheDocument();
  });
});
