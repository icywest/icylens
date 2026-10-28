import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { BackendStatus } from './BackendStatus';

describe('BackendStatus', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('shows connected only after a real healthy response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            status: 'healthy',
            service: 'iCYLENS',
            version: '1',
            message: 'ok',
          }),
          { status: 200 },
        ),
      ),
    );
    render(<BackendStatus />);
    expect(screen.getByRole('status')).toHaveTextContent('Checking API');
    expect(await screen.findByText('API connected')).toBeInTheDocument();
  });

  it('reports unavailable for failed or incompatible checks', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          new Response(JSON.stringify({ status: 'unknown' }), { status: 200 }),
        ),
    );
    render(<BackendStatus />);
    expect(await screen.findByText('API unavailable')).toBeInTheDocument();
  });
});
