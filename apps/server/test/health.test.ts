import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createPool } from '../src/db/pool.js';
import { AuditVerificationState, checkDatabase, isReady } from '../src/health/health.js';
import {
  createTestApp,
  createTestWorker,
  createUser,
  httpClient,
  loginAs,
  memberClient,
  owner,
  resetThrottle,
  type TestContext,
} from './helpers.js';

let ctx: TestContext;
beforeAll(async () => {
  ctx = await createTestApp();
});
afterAll(async () => ctx.close());
beforeEach(resetThrottle);

describe('liveness and readiness', () => {
  it('reports liveness without implying dependency health', async () => {
    const res = await httpClient(ctx.app).get('/health/live');
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'live', observedAt: expect.any(String) });
  });

  it('is ready when the database and schema are current', async () => {
    const res = await httpClient(ctx.app).get('/health/ready');
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.status).toBe('ready');
    expect(body.checks.map((c: { name: string; state: string }) => [c.name, c.state])).toEqual([
      ['database', 'OPERATIONAL'],
      ['schema', 'OPERATIONAL'],
    ]);
    expect(Date.parse(body.checks[0].observedAt)).not.toBeNaN();
  });

  it('is not ready when the required database is unavailable', async () => {
    const dead = createPool({ url: 'postgres://nobody:nothing@127.0.0.1:1/none', max: 1, statementTimeoutMs: 1000 });
    const checks = await checkDatabase(dead);
    await dead.end();
    expect(isReady(checks)).toBe(false);
    expect(checks.find((c) => c.name === 'database')!.state).toBe('UNAVAILABLE');
    // A dependent check is UNKNOWN, not healthy.
    expect(checks.find((c) => c.name === 'schema')!.state).toBe('UNKNOWN');
  });
});

describe('component status', () => {
  it('reports unknown, unverified, and foundation-only states honestly', async () => {
    await owner().query('DELETE FROM worker_heartbeats');
    const { client } = await memberClient(ctx, 'READ_ONLY_ANALYST');
    const res = await client.get('/api/system/status');
    expect(res.statusCode).toBe(200);
    const byKey = Object.fromEntries(
      res.json().components.map((c: { key: string; state: string }) => [c.key, c.state]),
    );
    expect(byKey).toMatchObject({
      api: 'OPERATIONAL',
      database: 'OPERATIONAL',
      worker: 'UNAVAILABLE',
      audit_chain: 'UNVERIFIED',
      sentinel: 'FOUNDATION_ONLY',
    });
  });

  it('reports a running worker, and a stale heartbeat as STALE', async () => {
    const worker = createTestWorker(ctx);
    await worker.start();
    const { client } = await memberClient(ctx, 'READ_ONLY_ANALYST');
    const state = async () =>
      (await client.get('/api/system/status')).json().components.find((c: { key: string }) => c.key === 'worker').state;
    expect(await state()).toBe('OPERATIONAL');
    await owner().query("UPDATE worker_heartbeats SET last_seen_at = now() - interval '5 minutes'");
    expect(await state()).toBe('STALE');
    await worker.stop();
  });

  it('marks audit verification stale or failed rather than healthy', () => {
    const s = new AuditVerificationState();
    expect(s.status().state).toBe('UNVERIFIED');
    s.set({ verified: true, eventsChecked: 1, firstInvalidPosition: null, reason: null, headPosition: '1', headHash: 'x', verifiedAt: new Date(Date.now() - 48 * 3600_000).toISOString() });
    expect(s.status().state).toBe('STALE');
    s.set({ verified: false, eventsChecked: 1, firstInvalidPosition: '1', reason: 'HASH_MISMATCH', headPosition: null, headHash: null, verifiedAt: new Date().toISOString() });
    expect(s.status().state).toBe('FAILED');
  });
});

describe('overview', () => {
  it('reports absent telemetry and findings as not implemented, never as safe', async () => {
    const { client } = await memberClient(ctx, 'TENANT_ADMIN');
    const res = await client.get('/api/overview');
    expect(res.statusCode).toBe(200);
    const o = res.json();
    expect(o.telemetry.state).toBe('NOT_IMPLEMENTED');
    expect(o.findings.state).toBe('NOT_IMPLEMENTED');
    expect(o.assets.total).toBe(0);
    expect(o.setupIssues.map((i: { code: string }) => i.code)).toEqual(
      expect.arrayContaining(['NO_ASSETS', 'NO_INTEGRATIONS']),
    );
    expect(JSON.stringify(o)).not.toMatch(/score/i);
  });

  it('flags unchecked integrations and test adapters', async () => {
    const { client } = await memberClient(ctx, 'TENANT_ADMIN');
    await client.post('/api/integrations', {
      provider: 'aegis.test_adapter',
      name: 'sim',
      config: { scenario: 'healthy' },
      grantedPermissions: ['test.read'],
    });
    const o = (await client.get('/api/overview')).json();
    expect(o.integrations).toMatchObject({ total: 1, testAdapters: 1, byEffectiveStatus: { CONFIGURED: 1 } });
    const codes = o.setupIssues.map((i: { code: string }) => i.code);
    expect(codes).toContain('INTEGRATIONS_UNCHECKED');
    expect(codes).toContain('TEST_ADAPTERS_IN_USE');
  });

  it('omits audit activity for roles without audit access', async () => {
    const { client } = await memberClient(ctx, 'READ_ONLY_ANALYST');
    expect((await client.get('/api/overview')).json().recentAudit).toBeNull();
  });

  it('requires a tenant', async () => {
    const user = await createUser();
    const client = await loginAs(ctx.app, user);
    expect((await client.get('/api/overview')).statusCode).toBe(403);
  });
});
