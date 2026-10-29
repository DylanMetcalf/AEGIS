import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { withTransaction } from '../src/db/pool.js';
import {
  addMember,
  auditEvents,
  createTenant,
  createTestApp,
  createUser,
  loginAs,
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

describe('tenant isolation through the API', () => {
  it('hides, and refuses to modify or delete, another tenant’s assets', async () => {
    const a = await memberClient(ctx, 'TENANT_ADMIN');
    const b = await memberClient(ctx, 'TENANT_ADMIN');
    const created = await b.client.post('/api/assets', validAsset());
    expect(created.statusCode).toBe(201);
    const id = created.json().id;

    expect((await a.client.get(`/api/assets/${id}`)).statusCode).toBe(404);
    expect((await a.client.patch(`/api/assets/${id}`, { version: 1, name: 'pwned' })).statusCode).toBe(404);
    expect((await a.client.delete(`/api/assets/${id}`)).statusCode).toBe(404);
    expect((await a.client.get('/api/assets')).json().items.map((x: { id: string }) => x.id)).not.toContain(id);

    const still = await b.client.get(`/api/assets/${id}`);
    expect(still.statusCode).toBe(200);
    expect(still.json().name).toBe(created.json().name);
  });

  it('ignores client-supplied tenant identifiers', async () => {
    const a = await memberClient(ctx, 'TENANT_ADMIN');
    const b = await memberClient(ctx, 'TENANT_ADMIN');
    const res = await a.client.post('/api/assets', { ...validAsset(), tenantId: b.tenantId });
    expect(res.statusCode).toBe(400);
    const { rows } = await owner().query('SELECT count(*)::int AS n FROM assets WHERE tenant_id = $1', [b.tenantId]);
    expect(rows[0].n).toBe(0);
  });

  it('refuses to switch into a tenant the user is not a member of, and audits it', async () => {
    const a = await memberClient(ctx, 'TENANT_ADMIN');
    const other = await createTenant();
    const res = await a.client.put('/api/session/tenant', { tenantId: other });
    expect(res.statusCode).toBe(403);
    expect((await a.client.get('/api/session')).json().activeTenant.id).toBe(a.tenantId);
    const events = await auditEvents("action = 'session.tenant_select' AND outcome = 'DENIED' AND target_id = $1", [other]);
    expect(events).toHaveLength(1);
  });

  it('cuts off access immediately when membership is suspended', async () => {
    const a = await memberClient(ctx, 'TENANT_ADMIN');
    expect((await a.client.get('/api/assets')).statusCode).toBe(200);
    await owner().query("UPDATE memberships SET status = 'SUSPENDED' WHERE principal_id = $1", [a.user.id]);
    expect((await a.client.get('/api/assets')).statusCode).toBe(403);
  });

  it('requires a selected tenant for tenant-scoped operations', async () => {
    const t1 = await createTenant();
    const t2 = await createTenant();
    const user = await createUser();
    await addMember(t1, user.id, 'TENANT_ADMIN');
    await addMember(t2, user.id, 'TENANT_ADMIN');
    const client = await loginAs(ctx.app, user); // two tenants: none auto-selected
    expect((await client.get('/api/session')).json().activeTenant).toBeNull();
    const res = await client.get('/api/assets');
    expect(res.statusCode).toBe(403);
    const denial = await auditEvents("action = 'authz.denied' AND actor_principal_id = $1", [user.id]);
    expect(denial.at(-1)!.reason_code).toBe('NO_TENANT_CONTEXT');
  });

  it('does not grant the system owner access to tenant data', async () => {
    const ownerUser = await createUser({ platformRole: 'SYSTEM_OWNER' });
    const client = await loginAs(ctx.app, ownerUser);
    expect((await client.get('/api/assets')).statusCode).toBe(403);
    expect((await client.get('/api/platform/tenants')).statusCode).toBe(200);
  });
});

describe('row-level security in the database', () => {
  async function seed() {
    const tA = await createTenant();
    const tB = await createTenant();
    const { rows } = await owner().query<{ id: string }>(
      `INSERT INTO assets (tenant_id, name, asset_type, environment, criticality, authorization_scope)
       VALUES ($1, 'b-asset', 'API', 'TEST', 'LOW', '{"statement":"s","identifiers":["x"]}') RETURNING id`,
      [tB],
    );
    return { tA, tB, assetB: rows[0]!.id };
  }

  it('returns nothing without tenant context (deny by default)', async () => {
    await seed();
    const { rows } = await withTransaction(ctx.pool, { tenantId: null, principalId: null }, (c) =>
      c.query('SELECT * FROM assets'),
    );
    expect(rows).toHaveLength(0);
    const noTx = await ctx.pool.query('SELECT count(*)::int AS n FROM integrations');
    expect(noTx.rows[0].n).toBe(0);
  });

  it('hides other tenants’ rows even when the query omits a tenant filter', async () => {
    const { tA, tB, assetB } = await seed();
    const rows = await withTransaction(ctx.pool, { tenantId: tA, principalId: null }, async (c) =>
      (await c.query('SELECT id, tenant_id FROM assets WHERE id = $1', [assetB])).rows,
    );
    expect(rows).toHaveLength(0);
    const visible = await withTransaction(ctx.pool, { tenantId: tB, principalId: null }, async (c) =>
      (await c.query('SELECT id FROM assets WHERE id = $1', [assetB])).rows,
    );
    expect(visible).toHaveLength(1);
  });

  it('rejects writes of rows into another tenant', async () => {
    const { tA, tB } = await seed();
    await expect(
      withTransaction(ctx.pool, { tenantId: tA, principalId: null }, (c) =>
        c.query(
          `INSERT INTO assets (tenant_id, name, asset_type, environment, criticality, authorization_scope)
           VALUES ($1, 'smuggled', 'API', 'TEST', 'LOW', '{"statement":"s","identifiers":["x"]}')`,
          [tB],
        ),
      ),
    ).rejects.toThrow(/row-level security/);
  });

  it('silently affects zero rows for cross-tenant UPDATE and DELETE', async () => {
    const { tA, assetB } = await seed();
    const counts = await withTransaction(ctx.pool, { tenantId: tA, principalId: null }, async (c) => [
      (await c.query("UPDATE assets SET name = 'x' WHERE id = $1", [assetB])).rowCount,
      (await c.query('DELETE FROM assets WHERE id = $1', [assetB])).rowCount,
    ]);
    expect(counts).toEqual([0, 0]);
    const { rows } = await owner().query('SELECT name FROM assets WHERE id = $1', [assetB]);
    expect(rows[0].name).toBe('b-asset');
  });

  it('prevents moving a row into another tenant via UPDATE', async () => {
    const { tA, tB } = await seed();
    const { rows } = await owner().query<{ id: string }>(
      `INSERT INTO assets (tenant_id, name, asset_type, environment, criticality, authorization_scope)
       VALUES ($1, 'a-asset', 'API', 'TEST', 'LOW', '{"statement":"s","identifiers":["x"]}') RETURNING id`,
      [tA],
    );
    await expect(
      withTransaction(ctx.pool, { tenantId: tA, principalId: null }, (c) =>
        c.query('UPDATE assets SET tenant_id = $2 WHERE id = $1', [rows[0]!.id, tB]),
      ),
    ).rejects.toThrow(/row-level security/);
  });

  it('enforces tenant-consistent relationships with composite foreign keys', async () => {
    const { tA, assetB } = await seed();
    // Even the table owner (which bypasses RLS) cannot attach tenant A's integration to tenant B's asset.
    await expect(
      owner().query(
        `INSERT INTO integrations (tenant_id, name, provider, asset_id) VALUES ($1, 'x', 'aegis.test_adapter', $2)`,
        [tA, assetB],
      ),
    ).rejects.toThrow(/foreign key/);
  });

  it('does not leak tenant context between pooled connections', async () => {
    const { tB } = await seed();
    await withTransaction(ctx.pool, { tenantId: tB, principalId: null }, (c) => c.query('SELECT 1'));
    // Exhaust the pool so the same physical connections are reused.
    const results = await Promise.all(
      Array.from({ length: 10 }, () =>
        ctx.pool.query<{ t: string | null }>("SELECT current_setting('aegis.tenant_id', true) AS t"),
      ),
    );
    for (const r of results) expect(r.rows[0]!.t ?? '').toBe('');
  });

  it('rejects malformed tenant context before touching the database', async () => {
    await expect(
      withTransaction(ctx.pool, { tenantId: "x' OR '1'='1", principalId: null }, (c) => c.query('SELECT 1')),
    ).rejects.toThrow(/Invalid tenant context/);
  });

  it('runs as a role that cannot bypass RLS or alter the schema', async () => {
    const { rows } = await ctx.pool.query<{ rolsuper: boolean; rolbypassrls: boolean }>(
      'SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user',
    );
    expect(rows[0]).toEqual({ rolsuper: false, rolbypassrls: false });
    await expect(ctx.pool.query('ALTER TABLE assets DISABLE ROW LEVEL SECURITY')).rejects.toThrow();
    await expect(ctx.pool.query('DROP POLICY assets_tenant_isolation ON assets')).rejects.toThrow();
    await expect(ctx.pool.query('CREATE TABLE evil (id int)')).rejects.toThrow();
  });

  it('prevents assigning administrative roles to AI worker identities at the database level', async () => {
    const t = await createTenant();
    const ai = await createUser({ kind: 'AI_WORKER' });
    await expect(addMember(t, ai.id, 'TENANT_ADMIN')).rejects.toThrow(/not permitted/);
    await expect(addMember(t, ai.id, 'AI_WORKER')).resolves.toBeTypeOf('string');
  });
});
