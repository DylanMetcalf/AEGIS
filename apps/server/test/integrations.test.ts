import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { effectiveStatus } from '../src/integrations/integrations.js';
import { httpProbeProvider } from '../src/integrations/providers/http-probe.js';
import { testAdapterProvider } from '../src/integrations/providers/test-adapter.js';
import {
  CapabilityError,
  assertCapabilityUsable,
  createProviderRegistry,
  resolveCredentialRef,
  runHealthCheck,
} from '../src/integrations/registry.js';
import type { Worker } from '../src/jobs/worker.js';
import {
  auditEvents,
  createTestApp,
  createTestWorker,
  memberClient,
  owner,
  resetThrottle,
  type HttpClient,
  type TestContext,
} from './helpers.js';

let ctx: TestContext;
let worker: Worker;
beforeAll(async () => {
  ctx = await createTestApp();
  worker = createTestWorker(ctx, { AEGIS_SECRET_PROBE_TOKEN: 'probe-secret-value-xyz' });
});
afterAll(async () => ctx.close());
beforeEach(resetThrottle);

async function drainJobs() {
  while (await worker.runOnce()) {
    /* run until the queue is empty */
  }
}

async function createTestIntegration(
  client: HttpClient,
  scenario: string,
  extra: Record<string, unknown> = {},
) {
  const res = await client.post('/api/integrations', {
    provider: 'aegis.test_adapter',
    name: `sim-${scenario}-${Math.random().toString(36).slice(2, 7)}`,
    config: { scenario },
    grantedPermissions: ['test.read'],
    ...extra,
  });
  expect(res.statusCode, res.body).toBe(201);
  return res.json();
}

describe('integration registry', () => {
  it('lists providers with explicit capability and test-adapter labelling', async () => {
    const { client } = await memberClient(ctx, 'INTEGRATION_ADMIN');
    const providers = (await client.get('/api/integration-providers')).json().items;
    const sim = providers.find((p: { id: string }) => p.id === 'aegis.test_adapter');
    const probe = providers.find((p: { id: string }) => p.id === 'http.endpoint_probe');
    expect(sim.testAdapter).toBe(true);
    expect(probe.testAdapter).toBe(false);
    expect(
      sim.capabilities.find((c: { key: string }) => c.key === 'events.collect').implemented,
    ).toBe(false);
  });

  it('excludes the test adapter when it is disabled', () => {
    const registry = createProviderRegistry({ testAdapterEnabled: false });
    expect(registry.get('aegis.test_adapter')).toBeNull();
    expect(registry.get('http.endpoint_probe')).not.toBeNull();
  });

  it('creates integrations as CONFIGURED, never CONNECTED', async () => {
    const { client } = await memberClient(ctx, 'INTEGRATION_ADMIN');
    const i = await createTestIntegration(client, 'healthy');
    expect(i.status).toBe('CONFIGURED');
    expect(i.effectiveStatus).toBe('CONFIGURED');
    expect(i.lastHealthAt).toBeNull();
    expect(i.availableCapabilities).toEqual(['connection.health_check']);
  });

  it('validates configuration, provider, permissions, and credential references', async () => {
    const { client } = await memberClient(ctx, 'INTEGRATION_ADMIN');
    const base = { provider: 'aegis.test_adapter', name: 'x', config: { scenario: 'healthy' } };
    const cases: [Record<string, unknown>, number][] = [
      [{ ...base, config: { scenario: 'nonsense' } }, 400],
      [{ ...base, config: { scenario: 'healthy', extra: true } }, 400],
      [{ ...base, provider: 'aws.everything' }, 422],
      [{ ...base, grantedPermissions: ['root.all'] }, 400],
      [{ ...base, credentialRef: 'env:DATABASE_URL' }, 400],
      [{ ...base, credentialRef: 'env:AEGIS_SECRET_' }, 400],
    ];
    for (const [body, status] of cases) {
      expect((await client.post('/api/integrations', body)).statusCode, JSON.stringify(body)).toBe(
        status,
      );
    }
  });

  it('rejects probe URLs that target private networks or embed credentials', async () => {
    const { client } = await memberClient(ctx, 'INTEGRATION_ADMIN');
    for (const url of [
      'http://example.com/health',
      'https://127.0.0.1/',
      'https://10.0.0.5/',
      'https://169.254.169.254/latest/meta-data/',
      'https://[::1]/',
      'https://[::ffff:127.0.0.1]/',
      'https://localhost/',
      'https://user:pass@example.com/',
      'file:///etc/passwd',
      'gopher://example.com/',
    ]) {
      const res = await client.post('/api/integrations', {
        provider: 'http.endpoint_probe',
        name: 'probe',
        config: { url },
        grantedPermissions: ['http.get'],
      });
      expect(res.statusCode, url).toBe(400);
    }
  });

  it('never returns credential values, only references', async () => {
    const { client } = await memberClient(ctx, 'INTEGRATION_ADMIN');
    const i = await createTestIntegration(client, 'healthy', {
      credentialRef: 'env:AEGIS_SECRET_PROBE_TOKEN',
    });
    expect(i.credentialRef).toBe('env:AEGIS_SECRET_PROBE_TOKEN');
    expect(i.hasCredential).toBe(true);
    const detail = await client.get(`/api/integrations/${i.id}`);
    expect(detail.body).not.toContain('probe-secret-value-xyz');
  });

  it('requires the credential capability to set credentials', async () => {
    const { client, tenantId } = await memberClient(ctx, 'TENANT_ADMIN');
    const operator = await memberClient(ctx, 'SECURITY_OPERATOR', tenantId);
    const res = await operator.client.post('/api/integrations', {
      provider: 'aegis.test_adapter',
      name: 'nope',
      config: { scenario: 'healthy' },
      credentialRef: 'env:AEGIS_SECRET_X',
    });
    expect(res.statusCode).toBe(403);
    expect(
      (await createTestIntegration(client, 'healthy', { credentialRef: 'env:AEGIS_SECRET_X' }))
        .hasCredential,
    ).toBe(true);
  });

  it('prevents attaching an integration to another tenant’s asset', async () => {
    const a = await memberClient(ctx, 'TENANT_ADMIN');
    const b = await memberClient(ctx, 'TENANT_ADMIN');
    const asset = (
      await b.client.post('/api/assets', {
        name: 'b-asset',
        assetType: 'API',
        environment: 'TEST',
        criticality: 'LOW',
        authorizationScope: {
          statement: 'Owner authorizes monitoring of this API.',
          identifiers: ['b.example.test'],
          authorizedBy: 'B',
          authorizedAt: '2026-01-01T00:00:00Z',
        },
      })
    ).json();
    const res = await a.client.post('/api/integrations', {
      provider: 'aegis.test_adapter',
      name: 'cross',
      config: { scenario: 'healthy' },
      assetId: asset.id,
    });
    expect(res.statusCode).toBe(400);
  });
});

describe('integration health checks (background jobs)', () => {
  it('runs a health check job and records the result', async () => {
    const { client } = await memberClient(ctx, 'INTEGRATION_ADMIN');
    const i = await createTestIntegration(client, 'healthy');
    const job = await client.post(`/api/integrations/${i.id}/health-checks`);
    expect(job.statusCode).toBe(202);
    expect(job.json().status).toBe('QUEUED');
    await drainJobs();
    expect((await client.get(`/api/jobs/${job.json().id}`)).json().status).toBe('SUCCEEDED');
    const detail = (await client.get(`/api/integrations/${i.id}`)).json();
    expect(detail.integration.status).toBe('CONNECTED');
    expect(detail.integration.effectiveStatus).toBe('CONNECTED');
    expect(detail.healthChecks[0]).toMatchObject({ result: 'CONNECTED', errorCode: null });
    expect(
      await auditEvents("action = 'integration.health_checked' AND target_id = $1", [i.id]),
    ).toHaveLength(1);
  });

  it.each([
    ['unreachable', 'DISCONNECTED', 'CONNECTION_REFUSED'],
    ['degraded', 'DEGRADED', 'SIMULATED_DEGRADATION'],
    ['auth_failure', 'DISCONNECTED', 'AUTHENTICATION_REJECTED'],
    ['crash', 'UNKNOWN', 'PROVIDER_ERROR'],
  ])('reports %s honestly', async (scenario, status, code) => {
    const { client } = await memberClient(ctx, 'INTEGRATION_ADMIN');
    const i = await createTestIntegration(client, scenario);
    await client.post(`/api/integrations/${i.id}/health-checks`);
    await drainJobs();
    const detail = (await client.get(`/api/integrations/${i.id}`)).json().integration;
    expect(detail.status).toBe(status);
    expect(detail.lastErrorCode).toBe(code);
  });

  it('bounds provider calls with a timeout', async () => {
    const outcome = await runHealthCheck(
      testAdapterProvider as never,
      { scenario: 'timeout', latencyMs: 0 },
      {
        network: { allowPrivateNetwork: false, allowInsecureHttp: false },
        resolveCredential: () => null,
      },
      200,
    );
    expect(outcome).toMatchObject({ result: 'DISCONNECTED', errorCode: 'TIMEOUT' });
  });

  it('reports a missing credential as an explicit failure', async () => {
    const { client } = await memberClient(ctx, 'INTEGRATION_ADMIN');
    const i = await createTestIntegration(client, 'healthy', {
      credentialRef: 'env:AEGIS_SECRET_DOES_NOT_EXIST',
    });
    await client.post(`/api/integrations/${i.id}/health-checks`);
    await drainJobs();
    const detail = (await client.get(`/api/integrations/${i.id}`)).json().integration;
    expect(detail).toMatchObject({
      status: 'DISCONNECTED',
      lastErrorCode: 'CREDENTIAL_UNAVAILABLE',
    });
  });

  it('refuses health checks when the required permission is not granted', async () => {
    const { client } = await memberClient(ctx, 'INTEGRATION_ADMIN');
    const i = await createTestIntegration(client, 'healthy', { grantedPermissions: [] });
    expect(i.availableCapabilities).toEqual([]);
    const res = await client.post(`/api/integrations/${i.id}/health-checks`);
    expect(res.statusCode).toBe(422);
    expect(res.json().error.code).toBe('PERMISSION_NOT_GRANTED');
  });

  it('does not run declared-but-unimplemented or undeclared capabilities', () => {
    expect(() =>
      assertCapabilityUsable(testAdapterProvider as never, 'events.collect', ['test.read']),
    ).toThrow(CapabilityError);
    expect(() =>
      assertCapabilityUsable(httpProbeProvider as never, 'events.collect', ['http.get']),
    ).toThrow(/CAPABILITY_NOT_DECLARED/);
  });

  it('deduplicates requests with the same idempotency key', async () => {
    const { client } = await memberClient(ctx, 'INTEGRATION_ADMIN');
    const i = await createTestIntegration(client, 'healthy');
    const a = await client.post(`/api/integrations/${i.id}/health-checks`, undefined, {
      'idempotency-key': 'abc-1',
    });
    const b = await client.post(`/api/integrations/${i.id}/health-checks`, undefined, {
      'idempotency-key': 'abc-1',
    });
    expect(a.statusCode).toBe(202);
    expect(b.statusCode).toBe(200);
    expect(b.json().id).toBe(a.json().id);
    const { rows } = await owner().query(
      "SELECT count(*)::int AS n FROM jobs WHERE payload->>'integrationId' = $1",
      [i.id],
    );
    expect(rows[0].n).toBe(1);
  });

  it('cancels a queued check when the configuration changes before it runs', async () => {
    const { client } = await memberClient(ctx, 'INTEGRATION_ADMIN');
    const i = await createTestIntegration(client, 'healthy');
    const job = (await client.post(`/api/integrations/${i.id}/health-checks`)).json();
    const upd = await client.patch(`/api/integrations/${i.id}`, {
      version: i.version,
      config: { scenario: 'degraded' },
    });
    expect(upd.statusCode).toBe(200);
    expect(upd.json()).toMatchObject({ status: 'CONFIGURED', configVersion: 2 });
    await drainJobs();
    const done = (await client.get(`/api/jobs/${job.id}`)).json();
    expect(done).toMatchObject({ status: 'CANCELLED', lastErrorCode: 'SUPERSEDED' });
    expect((await client.get(`/api/integrations/${i.id}`)).json().integration.status).toBe(
      'CONFIGURED',
    );
  });

  it('re-checks authorization when the job runs', async () => {
    const admin = await memberClient(ctx, 'INTEGRATION_ADMIN');
    const i = await createTestIntegration(admin.client, 'healthy');
    const job = (await admin.client.post(`/api/integrations/${i.id}/health-checks`)).json();
    await owner().query("UPDATE memberships SET status = 'SUSPENDED' WHERE principal_id = $1", [
      admin.user.id,
    ]);
    await drainJobs();
    const { rows } = await owner().query('SELECT status, last_error_code FROM jobs WHERE id = $1', [
      job.id,
    ]);
    expect(rows[0]).toEqual({ status: 'FAILED', last_error_code: 'AUTHORIZATION_REVOKED' });
    const { rows: integ } = await owner().query('SELECT status FROM integrations WHERE id = $1', [
      i.id,
    ]);
    expect(integ[0].status).toBe('CONFIGURED');
    expect(await auditEvents("action = 'job.denied' AND target_id = $1", [job.id])).toHaveLength(1);
  });

  it('executes jobs only within the requesting tenant', async () => {
    const a = await memberClient(ctx, 'INTEGRATION_ADMIN');
    const b = await memberClient(ctx, 'INTEGRATION_ADMIN');
    const ib = await createTestIntegration(b.client, 'healthy');
    // A job in tenant A that names tenant B's integration must not touch it.
    const ia = await createTestIntegration(a.client, 'healthy');
    const { rows } = await owner().query<{ id: string }>(
      `INSERT INTO jobs (tenant_id, actor_principal_id, kind, payload, max_attempts, timeout_ms)
       VALUES ($1, $2, 'integration.health_check', $3, 1, 5000) RETURNING id`,
      [a.tenantId, a.user.id, JSON.stringify({ integrationId: ib.id, configVersion: 1 })],
    );
    await drainJobs();
    const { rows: job } = await owner().query(
      'SELECT status, last_error_code FROM jobs WHERE id = $1',
      [rows[0]!.id],
    );
    expect(job[0]).toEqual({ status: 'FAILED', last_error_code: 'INTEGRATION_NOT_FOUND' });
    expect((await b.client.get(`/api/integrations/${ib.id}`)).json().integration.status).toBe(
      'CONFIGURED',
    );
    expect(ia.status).toBe('CONFIGURED');
  });

  it('fails jobs whose lease expired on the final attempt instead of leaving them running', async () => {
    const a = await memberClient(ctx, 'INTEGRATION_ADMIN');
    const { rows } = await owner().query<{ id: string }>(
      `INSERT INTO jobs (tenant_id, actor_principal_id, kind, status, attempts, max_attempts, timeout_ms,
                         locked_by, locked_until)
       VALUES ($1, $2, 'integration.health_check', 'RUNNING', 1, 1, 5000, 'dead-worker', now() - interval '1 minute')
       RETURNING id`,
      [a.tenantId, a.user.id],
    );
    await worker.tick();
    const { rows: job } = await owner().query(
      'SELECT status, last_error_code FROM jobs WHERE id = $1',
      [rows[0]!.id],
    );
    expect(job[0]).toEqual({ status: 'FAILED', last_error_code: 'LEASE_EXPIRED' });
  });
});

describe('integration lifecycle', () => {
  it('suspends, resumes, and revokes with validated transitions', async () => {
    const { client } = await memberClient(ctx, 'INTEGRATION_ADMIN');
    const i = await createTestIntegration(client, 'healthy', {
      credentialRef: 'env:AEGIS_SECRET_PROBE_TOKEN',
    });
    const s = await client.post(`/api/integrations/${i.id}/suspend`, { version: i.version });
    expect(s.json().status).toBe('SUSPENDED');
    expect((await client.post(`/api/integrations/${i.id}/health-checks`)).statusCode).toBe(409);
    const r = await client.post(`/api/integrations/${i.id}/resume`, { version: s.json().version });
    expect(r.json().status).toBe('CONFIGURED');
    const v = await client.post(`/api/integrations/${i.id}/revoke`, { version: r.json().version });
    expect(v.statusCode).toBe(200);
    expect(v.json()).toMatchObject({
      status: 'REVOKED',
      hasCredential: false,
      grantedPermissions: [],
    });
    const again = await client.post(`/api/integrations/${i.id}/resume`, {
      version: v.json().version,
    });
    expect(again.statusCode).toBe(409);
    expect(again.json().error.code).toBe('INVALID_STATE_TRANSITION');
    expect(
      (
        await client.patch(`/api/integrations/${i.id}`, {
          version: v.json().version,
          name: 'zombie',
        })
      ).statusCode,
    ).toBe(409);
  });

  it('reports stale health results as STALE', () => {
    const old = new Date(Date.now() - 2 * 3600_000);
    expect(effectiveStatus({ status: 'CONNECTED', last_health_at: old }, 3600_000, true)).toBe(
      'STALE',
    );
    expect(
      effectiveStatus({ status: 'CONNECTED', last_health_at: new Date() }, 3600_000, true),
    ).toBe('CONNECTED');
    expect(effectiveStatus({ status: 'CONNECTED', last_health_at: null }, 3600_000, true)).toBe(
      'STALE',
    );
    expect(
      effectiveStatus({ status: 'CONNECTED', last_health_at: new Date() }, 3600_000, false),
    ).toBe('UNKNOWN');
  });
});

describe('HTTPS endpoint probe against a real server', () => {
  let server: Server;
  let base: string;
  const seen: { auth?: string }[] = [];
  beforeAll(async () => {
    server = createServer((req, res) => {
      seen.push({ auth: req.headers.authorization });
      if (req.url === '/redirect') {
        res.writeHead(302, { location: 'http://169.254.169.254/' }).end();
      } else if (req.url === '/down') {
        res.writeHead(503).end();
      } else {
        res.writeHead(200, { 'content-type': 'text/plain' }).end('ok');
      }
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => new Promise<void>((r) => server.close(() => r())));

  const devNetwork = { allowPrivateNetwork: true, allowInsecureHttp: true };

  it('connects, sends the referenced credential, and reports latency', async () => {
    const config = httpProbeProvider.validateConfig({ url: `${base}/health` }, devNetwork);
    const outcome = await runHealthCheck(
      httpProbeProvider as never,
      config,
      {
        network: devNetwork,
        resolveCredential: () =>
          resolveCredentialRef('env:AEGIS_SECRET_T', { AEGIS_SECRET_T: 'tok-123' }),
      },
      5000,
    );
    expect(outcome.result).toBe('CONNECTED');
    expect(outcome.latencyMs).toBeGreaterThanOrEqual(0);
    expect(seen.at(-1)!.auth).toBe('Bearer tok-123');
  });

  it('does not follow redirects and reports unexpected status as degraded', async () => {
    const ctxNet = { network: devNetwork, resolveCredential: () => null };
    const redirect = await runHealthCheck(
      httpProbeProvider as never,
      httpProbeProvider.validateConfig({ url: `${base}/redirect` }, devNetwork),
      ctxNet,
      5000,
    );
    expect(redirect).toMatchObject({ result: 'DEGRADED', errorCode: 'UNEXPECTED_STATUS' });
    const down = await runHealthCheck(
      httpProbeProvider as never,
      httpProbeProvider.validateConfig({ url: `${base}/down` }, devNetwork),
      ctxNet,
      5000,
    );
    expect(down).toMatchObject({ result: 'DEGRADED', errorCode: 'UPSTREAM_ERROR_STATUS' });
  });

  it('refuses loopback destinations when private networks are not allowed', async () => {
    const outcome = await runHealthCheck(
      httpProbeProvider as never,
      { url: `${base}/health` },
      {
        network: { allowPrivateNetwork: false, allowInsecureHttp: true },
        resolveCredential: () => null,
      },
      5000,
    );
    expect(outcome).toMatchObject({ result: 'DISCONNECTED', errorCode: 'DESTINATION_NOT_ALLOWED' });
  });

  it('reports refused connections', async () => {
    const outcome = await runHealthCheck(
      httpProbeProvider as never,
      { url: 'http://127.0.0.1:1/' },
      { network: devNetwork, resolveCredential: () => null },
      5000,
    );
    expect(outcome).toMatchObject({ result: 'DISCONNECTED', errorCode: 'CONNECTION_REFUSED' });
  });
});
