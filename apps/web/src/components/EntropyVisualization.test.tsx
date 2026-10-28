import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { EntropyVisualization } from './EntropyVisualization';

describe('EntropyVisualization', () => {
  it('uses the real 0 to 8 bits-per-byte scale and text equivalent', () => {
    render(<EntropyVisualization value={4.25} totalBytes={64} />);
    const meter = screen.getByRole('meter', { name: 'Shannon entropy' });
    expect(meter).toHaveAttribute('aria-valuemin', '0');
    expect(meter).toHaveAttribute('aria-valuemax', '8');
    expect(meter).toHaveAttribute('aria-valuenow', '4.25');
    expect(meter.firstElementChild).toHaveStyle({ width: '53.125%' });
    expect(screen.getByText(/not a risk score/i)).toBeInTheDocument();
    expect(screen.queryByText(/high risk|low risk/i)).not.toBeInTheDocument();
  });

  it('shows an explicit empty state for missing or invalid entropy', () => {
    const { rerender } = render(<EntropyVisualization value={null} />);
    expect(screen.getByRole('status')).toHaveTextContent('unavailable');
    rerender(<EntropyVisualization value={9} />);
    expect(screen.queryByRole('meter')).not.toBeInTheDocument();
  });

  it('renders both valid endpoints without changing their meaning', () => {
    const { rerender } = render(<EntropyVisualization value={0} />);
    expect(screen.getByRole('meter')).toHaveAttribute('aria-valuenow', '0');
    rerender(<EntropyVisualization value={8} />);
    expect(screen.getByRole('meter')).toHaveAttribute('aria-valuenow', '8');
  });
});
