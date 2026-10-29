import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { api } from '../api/client';
import { StatusBadge } from './Status';
import { Loading } from './States';

describe('StatusBadge', () => {
  it('conveys state with text and a glyph, not colour alone', () => {
    render(<StatusBadge state="DISCONNECTED" />);
    const badge = screen.getByText('Disconnected');
    expect(badge).toHaveAttribute('data-state', 'DISCONNECTED');
    expect(badge.querySelector('[aria-hidden="true"]')?.textContent).toBeTruthy();
  });

  it('never renders unknown or foundation-only states as healthy', () => {
    for (const state of [
      'UNKNOWN',
      'FOUNDATION_ONLY',
      'STALE',
      'UNVERIFIED',
      'CONFIGURED',
      'SOMETHING_NEW',
    ]) {
      const { container, unmount } = render(<StatusBadge state={state} />);
      expect(container.querySelector('.tone-ok')).toBeNull();
      unmount();
    }
  });
});

describe('Loading', () => {
  it('announces itself to assistive technology', () => {
    render(<Loading label="Loading assets" />);
    expect(screen.getByRole('status')).toHaveAttribute('aria-busy', 'true');
    expect(screen.getByText('Loading assets…')).toBeInTheDocument();
  });
});

describe('api client', () => {
  it('refuses non-API and cross-origin paths', async () => {
    await expect(api('https://evil.example/api/x')).rejects.toThrow(/same-origin/);
    await expect(api('/login')).rejects.toThrow(/same-origin/);
  });
});

describe('post-login redirect', () => {
  it('accepts only plain in-app paths', async () => {
    const { safeReturnPath } = await import('../pages/LoginPage');
    expect(safeReturnPath('/assets/123')).toBe('/assets/123');
    for (const bad of [
      '//evil.example',
      '/\\evil.example',
      'https://evil.example',
      '/%2F%2Fevil',
      // eslint-disable-next-line no-script-url -- hostile input under test
      'javascript:x',
      42,
      null,
    ]) {
      expect(safeReturnPath(bad)).toBe('/');
    }
  });
});
