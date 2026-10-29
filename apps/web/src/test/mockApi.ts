import type { SessionInfo } from '@aegis/shared';
import { vi } from 'vitest';

type Handler = (
  init: RequestInit & { url: string },
) => { status: number; body?: unknown } | Promise<{ status: number; body?: unknown }>;

/** Route-table fetch mock. Unmatched requests fail loudly. */
export function mockApi(routes: Record<string, Handler>) {
  const calls: { method: string; url: string; body: unknown }[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = String(input);
    const method = init.method ?? 'GET';
    calls.push({ method, url, body: init.body ? JSON.parse(String(init.body)) : undefined });
    const key = Object.keys(routes).find((k) => {
      const [m, p] = k.split(' ');
      return m === method && (p === url || (p!.endsWith('*') && url.startsWith(p!.slice(0, -1))));
    });
    if (!key) throw new Error(`Unmocked request: ${method} ${url}`);
    const { status, body } = await routes[key]!({ ...init, url });
    return new Response(status === 204 ? null : JSON.stringify(body ?? {}), {
      status,
      headers: { 'content-type': 'application/json', 'x-request-id': 'req-test' },
    });
  });
  vi.stubGlobal('fetch', fetchMock);
  return { calls, fetchMock };
}

export const unauthenticated = () => ({
  status: 401,
  body: { error: { code: 'UNAUTHENTICATED', message: 'Authentication required', requestId: 'r1' } },
});

export function sessionFixture(overrides: Partial<SessionInfo> = {}): SessionInfo {
  return {
    principal: {
      id: 'p1',
      kind: 'HUMAN',
      displayName: 'Ada Analyst',
      email: 'ada@example.test',
      platformRole: null,
    },
    activeTenant: { id: 't1', slug: 'acme', displayName: 'Acme Corp', role: 'TENANT_ADMIN' },
    memberships: [{ tenantId: 't1', slug: 'acme', displayName: 'Acme Corp', role: 'TENANT_ADMIN' }],
    capabilities: [
      'tenant.read',
      'asset.read',
      'asset.create',
      'asset.update',
      'asset.delete',
      'integration.read',
      'audit.read',
      'membership.read',
    ],
    session: {
      id: 's1',
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      idleExpiresAt: new Date(Date.now() + 1800_000).toISOString(),
      reauthenticatedUntil: null,
    },
    ...overrides,
  };
}

export const emptyOverview = {
  generatedAt: new Date().toISOString(),
  tenant: { id: 't1', displayName: 'Acme Corp' },
  assets: { total: 0, byEnvironment: {}, byCriticality: {}, byCoverage: {} },
  integrations: { total: 0, byEffectiveStatus: {}, testAdapters: 0 },
  telemetry: {
    state: 'NOT_IMPLEMENTED',
    detail: 'No security telemetry is collected yet (Phase 2).',
  },
  findings: { state: 'NOT_IMPLEMENTED', detail: 'No detection engine is running (Phase 2).' },
  components: [
    {
      key: 'database',
      label: 'Database',
      required: true,
      state: 'OPERATIONAL',
      observedAt: new Date().toISOString(),
      detail: 'Reachable',
    },
    {
      key: 'worker',
      label: 'Background worker',
      required: false,
      state: 'UNKNOWN',
      observedAt: null,
      detail: 'No heartbeat',
    },
    {
      key: 'sentinel',
      label: 'SENTINEL supervision',
      required: false,
      state: 'FOUNDATION_ONLY',
      observedAt: null,
      detail: 'Contracts defined',
    },
  ],
  setupIssues: [{ code: 'NO_ASSETS', severity: 'info', message: 'No assets are registered.' }],
  recentAudit: [],
};
