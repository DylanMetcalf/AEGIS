import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  auditEvents,
  createTestApp,
  memberClient,
  owner,
  resetThrottle,
  validAsset,
  type TestContext,
} from './helpers.js';

let ctx: TestContext;
beforeAll(async () => {
  ctx = await createTestApp();
});
afterAll(async () => ctx.close());
beforeEach(resetThrottle);

describe('asset registry', () => {
  it('creates an asset with UNKNOWN coverage and records an audit event', async () => {
    const { client, tenantId, user } = await memberClient(ctx, 'SECURITY_OPERATOR');
    const res = await client.post('/api/assets', validAsset({ name: 'Payments API' }));
    expect(res.statusCode).toBe(201);
    const asset = res.json();
    expect(asset).toMatchObject({
      name: 'Payments API',
      status: 'ACTIVE',
      coverageState: 'UNKNOWN',
      version: 1,
    });
    const events = await auditEvents("action = 'asset.create' AND target_id = $1", [asset.id]);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      tenant_id: tenantId,
      actor_principal_id: user.id,
      outcome: 'SUCCESS',
    });
  });

  it('rejects clients setting coverage or other server-owned fields', async () => {
    const { client } = await memberClient(ctx, 'TENANT_ADMIN');
    for (const extra of [
      { coverageState: 'VERIFIED_WITHIN_DEFINED_SCOPE' },
      { id: crypto.randomUUID() },
      { version: 9 },
    ]) {
      expect((await client.post('/api/assets', validAsset(extra))).statusCode).toBe(400);
    }
  });

  it('validates input strictly', async () => {
    const { client } = await memberClient(ctx, 'TENANT_ADMIN');
    const cases = [
      validAsset({ assetType: 'SPACESHIP' }),
      validAsset({ name: '' }),
      validAsset({ name: 'x'.repeat(201) }),
      validAsset({ name: 'bad\u0007name' }),
      validAsset({
        authorizationScope: {
          statement: 'short',
          identifiers: [],
          authorizedBy: 'x',
          authorizedAt: 'yesterday',
        },
      }),
      validAsset({
        authorizationScope: { ...validAsset().authorizationScope, identifiers: ['<script>'] },
      }),
      validAsset({ description: 'x'.repeat(2001) }),
      { name: 'only a name' },
    ];
    for (const body of cases) {
      const res = await client.post('/api/assets', body);
      expect(res.statusCode, JSON.stringify(body).slice(0, 80)).toBe(400);
      expect(res.json().error.code).toBe('VALIDATION_FAILED');
    }
    expect((await client.get('/api/assets/not-a-uuid')).statusCode).toBe(400);
    expect((await client.get('/api/assets?limit=1000')).statusCode).toBe(400);
    expect((await client.get('/api/assets?sort=password')).statusCode).toBe(400);
    expect((await client.get('/api/assets?cursor=%27%3B%20DROP%20TABLE%20assets')).statusCode).toBe(
      400,
    );
  });

  it('stores untrusted text verbatim and returns it as JSON data, not markup', async () => {
    const { client } = await memberClient(ctx, 'TENANT_ADMIN');
    const payload = '<img src=x onerror=alert(1)>';
    const res = await client.post('/api/assets', validAsset({ description: payload }));
    expect(res.statusCode).toBe(201);
    expect(res.headers['content-type']).toMatch(/^application\/json/);
    expect(res.json().description).toBe(payload);
  });

  it('enforces unique names per tenant', async () => {
    const { client } = await memberClient(ctx, 'TENANT_ADMIN');
    expect((await client.post('/api/assets', validAsset({ name: 'Dup' }))).statusCode).toBe(201);
    const dup = await client.post('/api/assets', validAsset({ name: 'Dup' }));
    expect(dup.statusCode).toBe(409);
    const other = await memberClient(ctx, 'TENANT_ADMIN');
    expect((await other.client.post('/api/assets', validAsset({ name: 'Dup' }))).statusCode).toBe(
      201,
    );
  });

  it('uses optimistic concurrency for updates', async () => {
    const { client } = await memberClient(ctx, 'TENANT_ADMIN');
    const asset = (await client.post('/api/assets', validAsset())).json();
    const first = await client.patch(`/api/assets/${asset.id}`, {
      version: 1,
      criticality: 'HIGH',
    });
    expect(first.statusCode).toBe(200);
    expect(first.json().version).toBe(2);
    const stale = await client.patch(`/api/assets/${asset.id}`, { version: 1, criticality: 'LOW' });
    expect(stale.statusCode).toBe(409);
    expect((await client.get(`/api/assets/${asset.id}`)).json().criticality).toBe('HIGH');
  });

  it('validates status transitions server-side', async () => {
    const { client } = await memberClient(ctx, 'TENANT_ADMIN');
    const asset = (await client.post('/api/assets', validAsset())).json();
    const dec = await client.patch(`/api/assets/${asset.id}`, {
      version: 1,
      status: 'DECOMMISSIONED',
    });
    expect(dec.statusCode).toBe(200);
    const revive = await client.patch(`/api/assets/${asset.id}`, { version: 2, status: 'ACTIVE' });
    expect(revive.statusCode).toBe(409);
    expect(revive.json().error.code).toBe('INVALID_STATE_TRANSITION');
    const edit = await client.patch(`/api/assets/${asset.id}`, { version: 2, name: 'renamed' });
    expect(edit.statusCode).toBe(409);
  });

  it('denies writes to read-only roles and audits the denial without the payload', async () => {
    const { client, user } = await memberClient(ctx, 'READ_ONLY_ANALYST');
    const res = await client.post('/api/assets', validAsset({ description: 'secret-marker-123' }));
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('FORBIDDEN');
    const events = await auditEvents("action = 'authz.denied' AND actor_principal_id = $1", [
      user.id,
    ]);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ outcome: 'DENIED', reason_code: 'CAPABILITY_NOT_GRANTED' });
    expect((events[0]!.metadata as Record<string, unknown>).capability).toBe('asset.create');
    expect(JSON.stringify(events[0])).not.toContain('secret-marker-123');
    expect((await client.get('/api/assets')).statusCode).toBe(200);
  });

  it('requires reauthentication to delete a production asset', async () => {
    const { client, user } = await memberClient(ctx, 'SECURITY_ADMIN');
    const prod = (
      await client.post('/api/assets', validAsset({ environment: 'PRODUCTION' }))
    ).json();
    const staging = (
      await client.post('/api/assets', validAsset({ environment: 'STAGING' }))
    ).json();
    await owner().query(
      "UPDATE sessions SET reauthenticated_at = now() - interval '1 hour' WHERE principal_id = $1",
      [user.id],
    );

    const denied = await client.delete(`/api/assets/${prod.id}`);
    expect(denied.statusCode).toBe(403);
    expect(denied.json().error.code).toBe('REAUTHENTICATION_REQUIRED');
    expect((await client.delete(`/api/assets/${staging.id}`)).statusCode).toBe(204);

    expect(
      (await client.post('/api/auth/reauthenticate', { password: user.password })).statusCode,
    ).toBe(200);
    expect((await client.delete(`/api/assets/${prod.id}`)).statusCode).toBe(204);
    expect((await client.get(`/api/assets/${prod.id}`)).statusCode).toBe(404);
    expect(await auditEvents("action = 'asset.delete' AND target_id = $1", [prod.id])).toHaveLength(
      1,
    );
  });

  it('paginates with opaque cursors and supports filters', async () => {
    const { client } = await memberClient(ctx, 'TENANT_ADMIN');
    for (let i = 0; i < 5; i++) {
      await client.post(
        '/api/assets',
        validAsset({ name: `asset-${i}`, environment: i % 2 ? 'PRODUCTION' : 'TEST' }),
      );
    }
    const seen: string[] = [];
    let cursor: string | null = null;
    do {
      const url: string = `/api/assets?limit=2&sort=name&order=asc${cursor ? `&cursor=${cursor}` : ''}`;
      const page = (await client.get(url)).json();
      seen.push(...page.items.map((a: { name: string }) => a.name));
      cursor = page.nextCursor;
    } while (cursor);
    expect(seen).toEqual(['asset-0', 'asset-1', 'asset-2', 'asset-3', 'asset-4']);
    const prod = (await client.get('/api/assets?environment=PRODUCTION')).json();
    expect(prod.items).toHaveLength(2);
  });
});
