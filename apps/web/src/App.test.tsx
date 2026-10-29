import { PRODUCT_MODULES } from '@aegis/shared';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { SessionProvider } from './auth/SessionContext';
import { emptyOverview, mockApi, sessionFixture, unauthenticated } from './test/mockApi';
import { ToastProvider } from './ui/Toasts';

function renderApp(path = '/') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ToastProvider>
        <SessionProvider>
          <App />
        </SessionProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
}

afterEach(() => vi.unstubAllGlobals());

describe('authentication boundary', () => {
  it('sends anonymous users to a labelled sign-in form', async () => {
    mockApi({ 'GET /api/session': unauthenticated });
    renderApp('/assets');
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeInTheDocument();
    expect(screen.getByLabelText(/Email/)).toHaveAttribute('autocomplete', 'username');
    expect(screen.getByLabelText(/Password/)).toHaveAttribute('type', 'password');
  });

  it('shows the server’s generic error and clears the password on failure', async () => {
    mockApi({
      'GET /api/session': unauthenticated,
      'POST /api/auth/login': () => ({
        status: 401,
        body: {
          error: {
            code: 'INVALID_CREDENTIALS',
            message: 'Invalid email or password',
            requestId: 'r',
          },
        },
      }),
    });
    renderApp('/login');
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/Email/), 'a@b.test');
    await user.type(screen.getByLabelText(/Password/), 'nope-nope-nope');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByText('Invalid email or password')).toBeInTheDocument();
    expect(screen.getByLabelText(/Password/)).toHaveValue('');
  });

  it('signs in and lands on the overview', async () => {
    let authed = false;
    const { calls } = mockApi({
      'GET /api/session': () =>
        authed ? { status: 200, body: sessionFixture() } : unauthenticated(),
      'POST /api/auth/login': () => {
        authed = true;
        return { status: 200, body: { authenticated: true } };
      },
      'GET /api/overview': () => ({ status: 200, body: emptyOverview }),
    });
    renderApp('/login');
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/Email/), 'ada@example.test');
    await user.type(screen.getByLabelText(/Password/), 'correct horse battery');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('heading', { level: 1, name: 'Acme Corp' })).toBeInTheDocument();
    const login = calls.find((c) => c.url === '/api/auth/login')!;
    expect(login.body).toEqual({ email: 'ada@example.test', password: 'correct horse battery' });
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });
});

describe('navigation and honest capability status', () => {
  it('lists every product area', async () => {
    mockApi({
      'GET /api/session': () => ({ status: 200, body: sessionFixture() }),
      'GET /api/overview': () => ({ status: 200, body: emptyOverview }),
    });
    renderApp('/');
    const nav = await screen.findByRole('navigation', { name: 'Primary' });
    for (const m of PRODUCT_MODULES) {
      expect(
        within(nav).getByRole('link', { name: new RegExp(`^${m.label}`) }),
      ).toBeInTheDocument();
    }
  });

  it.each(PRODUCT_MODULES.filter((m) => m.state !== 'OPERATIONAL').map((m) => [m.label, m]))(
    '%s states that it is not operational and shows no data',
    async (_label, m) => {
      const { calls } = mockApi({
        'GET /api/session': () => ({ status: 200, body: sessionFixture() }),
      });
      renderApp(m.path);
      expect(await screen.findByRole('heading', { level: 1, name: m.label })).toBeInTheDocument();
      expect(
        screen.getAllByText(
          m.state === 'FOUNDATION_ONLY' ? 'Foundation only' : 'Not yet implemented',
        ).length,
      ).toBeGreaterThan(0);
      expect(screen.queryByText(/\d+%/)).not.toBeInTheDocument();
      // Only the session is fetched: nothing pretends to load module data.
      expect(calls.map((c) => c.url)).toEqual(['/api/session']);
    },
  );

  it('explains SENTINEL’s remaining shared dependencies', async () => {
    mockApi({ 'GET /api/session': () => ({ status: 200, body: sessionFixture() }) });
    renderApp('/sentinel');
    expect(await screen.findByRole('heading', { name: /Independence gaps/ })).toBeInTheDocument();
    expect(screen.getByText('Identity provider')).toBeInTheDocument();
  });
});

describe('overview', () => {
  it('reports missing telemetry instead of implying safety, with no score', async () => {
    mockApi({
      'GET /api/session': () => ({ status: 200, body: sessionFixture() }),
      'GET /api/overview': () => ({ status: 200, body: emptyOverview }),
    });
    renderApp('/');
    expect(await screen.findByText(/Security telemetry is not collected yet/)).toBeInTheDocument();
    expect(screen.getByText('Foundation only')).toBeInTheDocument();
    expect(screen.getByText('Unknown')).toBeInTheDocument();
    expect(screen.getByText(/There is no security score/)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/score\s*(of\s*)?\d/i);
  });

  it('shows a loading state, then an error state with the request id and a retry', async () => {
    let fail = true;
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    mockApi({
      'GET /api/session': () => ({ status: 200, body: sessionFixture() }),
      'GET /api/overview': async () =>
        (await gate, fail)
          ? {
              status: 503,
              body: {
                error: {
                  code: 'DEPENDENCY_UNAVAILABLE',
                  message: 'A required dependency is unavailable',
                  requestId: 'req-503',
                },
              },
            }
          : { status: 200, body: emptyOverview },
    });
    renderApp('/');
    expect(await screen.findByText('Loading overview…')).toBeInTheDocument();
    expect(screen.getByText('Loading overview…').closest('[role="status"]')).toHaveAttribute(
      'aria-busy',
      'true',
    );
    release();
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'A required dependency is unavailable',
    );
    expect(screen.getByText(/req-503/)).toBeInTheDocument();
    fail = false;
    await userEvent.setup().click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('heading', { level: 1, name: 'Acme Corp' })).toBeInTheDocument();
  });
});

describe('assets', () => {
  it('hides create controls from read-only roles (the server enforces regardless)', async () => {
    mockApi({
      'GET /api/session': () => ({
        status: 200,
        body: sessionFixture({ capabilities: ['tenant.read', 'asset.read'] }),
      }),
      'GET /api/assets*': () => ({ status: 200, body: { items: [], nextCursor: null } }),
    });
    renderApp('/assets');
    expect(await screen.findByText('No assets registered')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Register/ })).not.toBeInTheDocument();
  });

  it('validates the asset form with field-associated, accessible errors', async () => {
    const { calls } = mockApi({
      'GET /api/session': () => ({ status: 200, body: sessionFixture() }),
      'GET /api/assets*': () => ({ status: 200, body: { items: [], nextCursor: null } }),
    });
    renderApp('/assets');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Register asset' }));
    const dialog = await screen.findByRole('dialog', { name: 'Register asset' });
    await user.click(within(dialog).getByRole('button', { name: 'Register asset' }));
    const name = within(dialog).getByLabelText(/^Name/);
    expect(name).toHaveAttribute('aria-invalid', 'true');
    expect(name).toHaveAccessibleDescription(/>=1 characters|at least 1 character/);
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
  });
});

describe('reauthentication', () => {
  it('prompts for the password and retries the sensitive request once', async () => {
    let reauthed = false;
    const asset = {
      id: 'a1',
      name: 'Prod DB',
      assetType: 'DATABASE',
      environment: 'PRODUCTION',
      criticality: 'HIGH',
      status: 'ACTIVE',
      coverageState: 'UNKNOWN',
      description: null,
      version: 1,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      authorizationScope: {
        statement: 'Owner authorizes monitoring.',
        identifiers: ['db1'],
        authorizedBy: 'Owner',
        authorizedAt: '2026-01-01T00:00:00Z',
      },
    };
    const { calls } = mockApi({
      'GET /api/session': () => ({ status: 200, body: sessionFixture() }),
      'GET /api/assets/a1': () => ({ status: 200, body: asset }),
      'GET /api/assets*': () => ({ status: 200, body: { items: [], nextCursor: null } }),
      'DELETE /api/assets/a1': () =>
        reauthed
          ? { status: 204 }
          : {
              status: 403,
              body: {
                error: {
                  code: 'REAUTHENTICATION_REQUIRED',
                  message: 'Confirm your password to continue',
                  requestId: 'r',
                },
              },
            },
      'POST /api/auth/reauthenticate': () => {
        reauthed = true;
        return { status: 200, body: { reauthenticatedUntil: new Date().toISOString() } };
      },
    });
    renderApp('/assets/a1');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Delete' }));
    const confirm = await screen.findByRole('dialog', { name: /Delete Prod DB/ });
    const button = within(confirm).getByRole('button', { name: 'Delete asset' });
    expect(button).toBeDisabled();
    await user.type(within(confirm).getByLabelText(/Type/), 'Prod DB');
    await user.click(button);
    const reauth = await screen.findByRole('dialog', { name: 'Confirm it’s you' });
    await user.type(within(reauth).getByLabelText(/Password/), 'my-password');
    await user.click(within(reauth).getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(calls.filter((c) => c.method === 'DELETE')).toHaveLength(2));
    expect(calls.find((c) => c.url === '/api/auth/reauthenticate')!.body).toEqual({
      password: 'my-password',
    });
  });
});
