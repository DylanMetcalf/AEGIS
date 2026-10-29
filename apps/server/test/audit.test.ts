import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { recordAudit, verifyAuditChain } from '../src/audit/audit.js';
import { withTransaction } from '../src/db/pool.js';
import {
  createTestApp,
  createUser,
  loginAs,
  memberClient,
  owner,
  resetThrottle,
  superuser,
  validAsset,
  type TestContext,
} from './helpers.js';

let ctx: TestContext;
beforeAll(async () => {
  ctx = await createTestApp();
});
afterAll(async () => ctx.close());
beforeEach(resetThrottle);

describe('audit log', () => {
  it('redacts sensitive metadata before storage', async () => {
    const tenant = (await memberClient(ctx, 'TENANT_ADMIN')).tenantId;
    await withTransaction(ctx.pool, { tenantId: tenant, principalId: null }, (c) =>
      recordAudit(c, {
        tenantId: tenant,
        actorPrincipalId: null,
        actorType: 'SYSTEM',
        action: 'test.redaction',
        outcome: 'SUCCESS',
        metadata: {
          password: 'pw-123',
          nested: { apiKey: 'k-456', authorization: 'Bearer abc', ok: 'visible' },
          sessionToken: 't-789',
          credentialRef: 'env:AEGIS_SECRET_OK',
        },
      }),
    );
    const { rows } = await owner().query("SELECT metadata FROM audit_events WHERE action = 'test.redaction'");
    const stored = JSON.stringify(rows[0].metadata);
    for (const secret of ['pw-123', 'k-456', 'Bearer abc', 't-789']) expect(stored).not.toContain(secret);
    expect(rows[0].metadata.nested.ok).toBe('visible');
    expect(rows[0].metadata.credentialRef).toBe('env:AEGIS_SECRET_OK');
  });

  it('cannot be modified or deleted by the application role', async () => {
    await expect(ctx.pool.query("UPDATE audit_events SET action = 'x.y'")).rejects.toThrow(/permission denied/);
    await expect(ctx.pool.query('DELETE FROM audit_events')).rejects.toThrow(/permission denied/);
    await expect(ctx.pool.query('TRUNCATE audit_events')).rejects.toThrow(/permission denied/);
  });

  it('cannot be modified by the schema owner without first disabling triggers', async () => {
    await expect(owner().query("UPDATE audit_events SET action = 'x.y'")).rejects.toThrow(/append-only/);
    await expect(owner().query('DELETE FROM audit_events')).rejects.toThrow(/append-only/);
    await expect(owner().query('TRUNCATE audit_events')).rejects.toThrow(/append-only/);
  });

  it('assigns chain positions and hashes itself, ignoring client-supplied values', async () => {
    const tenant = (await memberClient(ctx, 'TENANT_ADMIN')).tenantId;
    await withTransaction(ctx.pool, { tenantId: tenant, principalId: null }, (c) =>
      c.query(
        `INSERT INTO audit_events (chain_position, tenant_id, actor_type, action, outcome, hash, occurred_at)
         VALUES (1, $1, 'SYSTEM', 'test.forged', 'SUCCESS', '\\x00', '2000-01-01')`,
        [tenant],
      ),
    );
    const { rows } = await owner().query("SELECT chain_position, occurred_at FROM audit_events WHERE action = 'test.forged'");
    expect(Number(rows[0].chain_position)).toBeGreaterThan(1);
    expect(new Date(rows[0].occurred_at).getFullYear()).toBeGreaterThanOrEqual(2026);
    expect((await verifyAuditChain(ctx.pool)).verified).toBe(true);
  });

  it('keeps the chain intact under concurrent writers', async () => {
    const tenant = (await memberClient(ctx, 'TENANT_ADMIN')).tenantId;
    await Promise.all(
      Array.from({ length: 20 }, (_, n) =>
        withTransaction(ctx.pool, { tenantId: tenant, principalId: null }, (c) =>
          recordAudit(c, { tenantId: tenant, actorPrincipalId: null, actorType: 'SYSTEM', action: 'test.concurrent', outcome: 'SUCCESS', metadata: { n } }),
        ),
      ),
    );
    const v = await verifyAuditChain(ctx.pool);
    expect(v.verified).toBe(true);
    expect(v.eventsChecked).toBeGreaterThanOrEqual(20);
  });

  it('cannot write events into another tenant’s log', async () => {
    const a = (await memberClient(ctx, 'TENANT_ADMIN')).tenantId;
    const b = (await memberClient(ctx, 'TENANT_ADMIN')).tenantId;
    await expect(
      withTransaction(ctx.pool, { tenantId: a, principalId: null }, (c) =>
        recordAudit(c, { tenantId: b, actorPrincipalId: null, actorType: 'SYSTEM', action: 'test.cross', outcome: 'SUCCESS' }),
      ),
    ).rejects.toThrow(/row-level security/);
  });

  it('serves tenant audit events only to authorized roles and only for their tenant', async () => {
    const admin = await memberClient(ctx, 'TENANT_ADMIN');
    await admin.client.post('/api/assets', validAsset());
    const auditor = await memberClient(ctx, 'AUDITOR', admin.tenantId);
    const events = (await auditor.client.get('/api/audit-events?limit=100')).json().items;
    expect(events.length).toBeGreaterThan(0);
    expect(events.every((e: { tenantId: string }) => e.tenantId === admin.tenantId)).toBe(true);
    expect(events.map((e: { action: string }) => e.action)).toContain('asset.create');

    const analyst = await memberClient(ctx, 'READ_ONLY_ANALYST', admin.tenantId);
    expect((await analyst.client.get('/api/audit-events')).statusCode).toBe(403);
  });

  it('lets the system owner verify the chain and detects tampering by a privileged attacker', async () => {
    const sysOwner = await createUser({ platformRole: 'SYSTEM_OWNER' });
    const client = await loginAs(ctx.app, sysOwner);
    const ok = (await client.post('/api/platform/audit/verify')).json();
    expect(ok.verified).toBe(true);
    expect(ok.headHash).toMatch(/^[0-9a-f]{64}$/);

    // Simulate a database superuser rewriting history.
    const su = superuser();
    const { rows } = await su.query<{ chain_position: string; metadata: unknown }>(
      'SELECT chain_position, metadata FROM audit_events ORDER BY chain_position LIMIT 1 OFFSET 2',
    );
    const target = rows[0]!;
    await su.query('ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_mutation');
    try {
      await su.query(`UPDATE audit_events SET metadata = '{"rewritten": true}' WHERE chain_position = $1`, [target.chain_position]);
      const tampered = (await client.post('/api/platform/audit/verify')).json();
      expect(tampered.verified).toBe(false);
      expect(tampered.reason).toBe('HASH_MISMATCH');
      expect(tampered.firstInvalidPosition).toBe(target.chain_position);
      const status = (await client.get('/api/platform/audit-events?action=audit.chain_verify&limit=1')).json().items[0];
      expect(status.outcome).toBe('FAILURE');
    } finally {
      await su.query('UPDATE audit_events SET metadata = $2 WHERE chain_position = $1', [target.chain_position, target.metadata]);
      await su.query('ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_mutation');
    }
    expect((await client.post('/api/platform/audit/verify')).json().verified).toBe(true);
  });

  it('does not let tenant admins verify the platform chain', async () => {
    const admin = await memberClient(ctx, 'TENANT_ADMIN');
    expect((await admin.client.post('/api/platform/audit/verify')).statusCode).toBe(403);
  });
});
