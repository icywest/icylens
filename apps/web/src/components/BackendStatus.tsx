import { useEffect, useState } from 'react';
import { API_BASE_URL } from '../lib/api';

type ConnectionState = 'checking' | 'connected' | 'unavailable';

export function BackendStatus() {
  const [state, setState] = useState<ConnectionState>('checking');

  useEffect(() => {
    let mounted = true;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 5000);

    void fetch(`${API_BASE_URL}/api/v1/health/`, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    })
      .then(async (response) => {
        if (!response.ok) throw new Error('Health request failed');
        const payload: unknown = await response.json();
        if (
          typeof payload !== 'object' ||
          payload === null ||
          !('status' in payload) ||
          payload.status !== 'healthy'
        ) {
          throw new Error('Health response incompatible');
        }
        if (mounted) setState('connected');
      })
      .catch(() => {
        if (mounted) setState('unavailable');
      })
      .finally(() => window.clearTimeout(timeout));

    return () => {
      mounted = false;
      window.clearTimeout(timeout);
      controller.abort();
    };
  }, []);

  const text =
    state === 'checking'
      ? 'Checking API'
      : state === 'connected'
        ? 'API connected'
        : 'API unavailable';

  return (
    <div
      className="connection-status"
      data-state={state}
      role="status"
      aria-live="polite"
    >
      <span className="connection-status__dot" aria-hidden="true" />
      <span>{text}</span>
    </div>
  );
}
