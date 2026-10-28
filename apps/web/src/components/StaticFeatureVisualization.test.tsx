import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { staticAnalysisFixture } from '../test/fixtures';
import { StaticFeatureVisualization } from './StaticFeatureVisualization';

describe('StaticFeatureVisualization', () => {
  it('renders real counts and the declared retention-cap scale', () => {
    render(
      <StaticFeatureVisualization
        strings={staticAnalysisFixture.content.strings}
        indicators={staticAnalysisFixture.indicators}
        indicatorsTruncated={false}
      />,
    );
    expect(screen.getByText('4')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('3 / 100')).toBeInTheDocument();
    expect(screen.getByRole('meter')).toHaveAttribute('aria-valuemax', '100');
    expect(
      screen.getByText(/does not represent severity/i),
    ).toBeInTheDocument();
  });

  it('discloses truncation and handles an empty indicator list', () => {
    render(
      <StaticFeatureVisualization
        strings={{ ...staticAnalysisFixture.content.strings, truncated: true }}
        indicators={[]}
        indicatorsTruncated
      />,
    );
    expect(screen.getByText('Strings truncated')).toBeInTheDocument();
    expect(screen.getByText('Indicators truncated')).toBeInTheDocument();
    expect(
      screen.getByText(/No informational text-pattern indicators/i),
    ).toBeInTheDocument();
  });
});
