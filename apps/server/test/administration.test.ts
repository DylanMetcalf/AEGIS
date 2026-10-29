import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  auditEvents,
  createTestApp,
  createUser,
  loginAs,
  memberClient,
  owner,
  resetThrottle,
  uid,
  type TestContext,
} from './helpers.js';

let ctx: TestContext;
beforeAll(async () => {
  ctx = await createTestApp();
});
afterAll(async () => ctx.close());
beforeEach(resetThrottle);

describe('tenant membership administration', () => {
  it('lets a tenant admin add a member and change their role', async () => {
    const admin = await memberClient(ctx, 'TENANT_ADMIN');
    const newcomer = await createUser();
    const added = await admin.client.post('/api/members', {
      email: newcomer.email,
      role: 'AUDITOR',
    });
    expect(added.statusCode).toBe(201);
    const memberId = added.json().id;
    const changed = await admin.client.patch(`/api/members/${memberId}`, {
      role: 'SECURITY_OPERATOR',
    });
    expect(changed.statusCode).toBe(200);
    expect(changed.json().role).toBe('SECURITY_OPERATOR');
    const events = await auditEvents("action = 'membership.update' AND target_id = $1", [memberId]);
    expect(events[0]!.metadata).toMatchObject({
      from: { role: 'AUDITOR' },
      to: { role: 'SECURITY_OPERATOR' },
    });

    const newcomerClient = await loginAs(ctx.app, newcomer, admin.tenantId);
    expect((await newcomerClient.get('/api/session')).json().activeTenant.role).toBe(
      'SECURITY_OPERATOR',
    );
  });

  it('does not let non-admins manage membership', async () => {
    for (const role of ['SECURITY_ADMIN', 'AUDITOR', 'INTEGRATION_ADMIN'] as const) {
      const m = await memberClient(ctx, role);
      const target = await createUser();
      expect(
        (await m.client.post('/api/members', { email: target.email, role: 'TENANT_ADMIN' }))
          .statusCode,
      ).toBe(403);
    }
  });

  it('prevents removing the last tenant administrator', async () => {
    const admin = await memberClient(ctx, 'TENANT_ADMIN');
    const members = (await admin.client.get('/api/members')).json().items;
    const self = members.find((m: { principalId: string }) => m.principalId === admin.user.id);
    const res = await admin.client.patch(`/api/members/${self.id}`, { role: 'AUDITOR' });
    expect(res.statusCode).toBe(422);
    expect(res.json().error.code).toBe('LAST_TENANT_ADMIN');
    expect(
      (await admin.client.patch(`/api/members/${self.id}`, { status: 'REMOVED' })).statusCode,
    ).toBe(422);
  });

  it('refuses human roles for AI worker identities', async () => {
    const admin = await memberClient(ctx, 'TENANT_ADMIN');
    const ai = await createUser({ kind: 'AI_WORKER' });
    await owner().query('UPDATE principals SET email = $2 WHERE id = $1', [
      ai.id,
      `ai-${uid()}@example.test`,
    ]);
    const { rows } = await owner().query('SELECT email FROM principals WHERE id = $1', [ai.id]);
    const res = await admin.client.post('/api/members', {
      email: rows[0].email,
      role: 'TENANT_ADMIN',
    });
    expect(res.statusCode).toBe(400);
  });

  it('cannot address memberships of another tenant', async () => {
    const a = await memberClient(ctx, 'TENANT_ADMIN');
    const b = await memberClient(ctx, 'TENANT_ADMIN');
    const bMembers = (await b.client.get('/api/members')).json().items;
    const res = await a.client.patch(`/api/members/${bMembers[0].id}`, { role: 'AUDITOR' });
    expect(res.statusCode).toBe(404);
  });

  it('requires recent reauthentication for membership changes', async () => {
    const admin = await memberClient(ctx, 'TENANT_ADMIN');
    await owner().query('UPDATE sessions SET reauthenticated_at = NULL WHERE principal_id = $1', [
      admin.user.id,
    ]);
    const target = await createUser();
    const res = await admin.client.post('/api/members', { email: target.email, role: 'AUDITOR' });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('REAUTHENTICATION_REQUIRED');
  });
});

describe('platform administration', () => {
  it('lets only a system owner create tenants', async () => {
    const sysOwner = await createUser({ platformRole: 'SYSTEM_OWNER' });
    const client = await loginAs(ctx.app, sysOwner);
    const slug = `acme-${uid()}`;
    const res = await client.post('/api/platform/tenants', { slug, displayName: 'Acme' });
    expect(res.statusCode).toBe(201);
    const tenants = (await client.get('/api/platform/tenants')).json().items;
    expect(tenants.map((t: { slug: string }) => t.slug)).toContain(slug);

    const admin = await memberClient(ctx, 'TENANT_ADMIN');
    expect(
      (await admin.client.post('/api/platform/tenants', { slug: `x-${uid()}`, displayName: 'X' }))
        .statusCode,
    ).toBe(403);
    expect((await admin.client.get('/api/platform/tenants')).statusCode).toBe(403);
  });

  it('exposes only platform-level audit events in platform scope', async () => {
    const sysOwner = await createUser({ platformRole: 'SYSTEM_OWNER' });
    const client = await loginAs(ctx.app, sysOwner);
    const events = (await client.get('/api/platform/audit-events?limit=100')).json().items;
    expect(events.length).toBeGreaterThan(0);
    expect(events.every((e: { tenantId: string | null }) => e.tenantId === null)).toBe(true);
  });
});
