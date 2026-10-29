import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { authorize } from '../src/authz/authorize.js';
import { loadActorForTenant } from '../src/authz/load-actor.js';
import { computeCoverage } from '../src/coverage/coverage.js';
import { INJECTION_SIGNATURES } from '../src/detection/rules.js';
import type { Worker } from '../src/jobs/worker.js';
import {
  auditEvents,
  createTestApp,
  createTestWorker,
  memberClient,
  owner,
  resetThrottle,
  superuser,
  uid,
  validAsset,
  type HttpClient,
  type TestContext,
} from './helpers.js';

let ctx: TestContext;
let worker: Worker;
beforeAll(async () => {
  ctx = await createTestApp();
  worker = createTestWorker(ctx);
});
afterAll(async () => ctx.close());
beforeEach(resetThrottle);

const drain = async () => {
  while (await worker.runOnce()) {
    /* until empty */
  }
};

interface Setup {
  admin: HttpClient;
  tenantId: string;
  assetId: string;
  integrationId: string;
  token: string;
}

async function setup(extra: Record<string, unknown> = {}): Promise<Setup> {
  const { client: admin, tenantId } = await memberClient(ctx, 'TENANT_ADMIN');
  const asset = (await admin.post('/api/assets', validAsset())).json();
  const integ = await admin.post('/api/integrations', {
    provider: 'aegis.event_ingest',
    name: `intake-${uid()}`,
    config: {},
    grantedPermissions: ['events.ingest'],
    assetId: asset.id,
    ...extra,
  });
  expect(integ.statusCode, integ.body).toBe(201);
  const tok = await admin.post(`/api/integrations/${integ.json().id}/ingest-tokens`);
  expect(tok.statusCode, tok.body).toBe(201);
  return {
    admin,
    tenantId,
    assetId: asset.id,
    integrationId: integ.json().id,
    token: tok.json().token,
  };
}

const ingest = (token: string | null, body: unknown, headers: Record<string, string> = {}) =>
  ctx.app.inject({
    method: 'POST',
    url: '/ingest/v1/events',
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    payload: JSON.stringify(body),
  });

const now = () => new Date().toISOString();
const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();
const failures = (ip: string, n: number, user = 'alice', newestSecondsAgo = 30) =>
  Array.from({ length: n }, (_, i) => ({
    eventType: 'auth.failure',
    observedAt: ago(newestSecondsAgo + n - i),
    actor: { ip, userId: user },
    sourceEventId: `f-${ip}-${i}-${uid()}`,
  }));

describe('ingest tokens', () => {
  it('are shown once, stored hashed, and listed by prefix only', async () => {
    const s = await setup();
    expect(s.token).toMatch(/^aegis_ing_[A-Za-z0-9_-]{43}$/);
    const list = await s.admin.get(`/api/integrations/${s.integrationId}/ingest-tokens`);
    expect(list.body).not.toContain(s.token);
    expect(list.json().items[0].prefix).toBe(s.token.slice(0, 14));
    const { rows } = await owner().query(
      "SELECT 1 FROM ingest_tokens WHERE encode(token_hash, 'escape') LIKE '%' || $1 || '%'",
      [s.token.slice(10)],
    );
    expect(rows).toHaveLength(0);
    expect(
      await auditEvents("action = 'integration.ingest_token.create' AND target_id = $1", [
        s.integrationId,
      ]),
    ).toHaveLength(1);
  });

  it('require the credential capability and an event-collecting provider', async () => {
    const s = await setup();
    const op = await memberClient(ctx, 'SECURITY_OPERATOR', s.tenantId);
    expect(
      (await op.client.post(`/api/integrations/${s.integrationId}/ingest-tokens`)).statusCode,
    ).toBe(403);
    const sim = (
      await s.admin.post('/api/integrations', {
        provider: 'aegis.test_adapter',
        name: `sim-${uid()}`,
        config: { scenario: 'healthy' },
      })
    ).json();
    expect((await s.admin.post(`/api/integrations/${sim.id}/ingest-tokens`)).statusCode).toBe(422);
  });

  it('give the service identity only ingest and detection capabilities', async () => {
    const s = await setup();
    const { rows } = await owner().query(
      'SELECT service_principal_id FROM integrations WHERE id = $1',
      [s.integrationId],
    );
    const actor = await loadActorForTenant(ctx.pool, s.tenantId, rows[0].service_principal_id);
    const opts = { reauthWindowMs: 60_000 };
    expect(actor?.kind).toBe('SERVICE');
    expect(authorize(actor, 'telemetry.ingest', opts).allowed).toBe(true);
    for (const cap of [
      'asset.create',
      'finding.update',
      'integration.manage',
      'membership.manage',
      'audit.read',
    ]) {
      expect(authorize(actor, cap, opts).allowed, cap).toBe(false);
    }
  });
});

describe('telemetry ingestion', () => {
  it('rejects missing, malformed, unknown, and revoked tokens', async () => {
    const s = await setup();
    const body = { events: [{ eventType: 'auth.success', observedAt: now() }] };
    expect((await ingest(null, body)).statusCode).toBe(401);
    expect((await ingest('not-a-token', body)).statusCode).toBe(401);
    expect((await ingest(`aegis_ing_${'A'.repeat(43)}`, body)).statusCode).toBe(401);
    const tokens = (await s.admin.get(`/api/integrations/${s.integrationId}/ingest-tokens`)).json()
      .items;
    expect(
      (await s.admin.delete(`/api/integrations/${s.integrationId}/ingest-tokens/${tokens[0].id}`))
        .statusCode,
    ).toBe(204);
    expect((await ingest(s.token, body)).statusCode).toBe(401);
  });

  it('does not accept browser sessions, and tokens do not grant API access', async () => {
    const s = await setup();
    const viaCookie = await ctx.app.inject({
      method: 'POST',
      url: '/ingest/v1/events',
      headers: { 'content-type': 'application/json', cookie: `aegis_session=${s.admin.cookie}` },
      payload: JSON.stringify({ events: [{ eventType: 'auth.success', observedAt: now() }] }),
    });
    expect(viaCookie.statusCode).toBe(401);
    const apiWithToken = await ctx.app.inject({
      method: 'GET',
      url: '/api/assets',
      headers: { authorization: `Bearer ${s.token}` },
    });
    expect(apiWithToken.statusCode).toBe(401);
  });

  it('accepts a valid batch, marks the integration connected, and deduplicates', async () => {
    const s = await setup();
    const events = [
      {
        eventType: 'auth.success',
        observedAt: now(),
        actor: { ip: '203.0.113.7', userId: 'bob' },
        sourceEventId: 'evt-1',
      },
      {
        eventType: 'config.changed',
        observedAt: now(),
        attributes: { setting: 'mfa', value: false },
      },
    ];
    const first = await ingest(s.token, { events });
    expect(first.statusCode, first.body).toBe(202);
    expect(first.json()).toMatchObject({ accepted: 2, duplicates: 0 });
    const again = await ingest(s.token, { events });
    expect(again.json()).toMatchObject({ accepted: 0, duplicates: 2 });
    const integ = (await s.admin.get(`/api/integrations/${s.integrationId}`)).json().integration;
    expect(integ.status).toBe('CONNECTED');
    const listed = (await s.admin.get('/api/telemetry-events?limit=10')).json().items;
    expect(listed).toHaveLength(2);
    expect(listed.find((e: { eventType: string }) => e.eventType === 'auth.success').actorIp).toBe(
      '203.0.113.7',
    );
  });

  it('validates every event strictly', async () => {
    const s = await setup();
    const bad = [
      { events: [] },
      { events: [{ eventType: 'malware.found', observedAt: now() }] },
      { events: [{ eventType: 'auth.success', observedAt: now(), tenantId: s.tenantId }] },
      { events: [{ eventType: 'auth.success', observedAt: now(), actor: { ip: '999.1.1.1' } }] },
      { events: [{ eventType: 'auth.success', observedAt: now(), attributes: { 'Bad-Key': 1 } }] },
      {
        events: [
          { eventType: 'auth.success', observedAt: now(), attributes: { a: 'x'.repeat(513) } },
        ],
      },
      {
        events: [
          { eventType: 'auth.success', observedAt: new Date(Date.now() + 3600_000).toISOString() },
        ],
      },
      { events: [{ eventType: 'auth.success', observedAt: ago(8 * 86400) }] },
      {
        events: Array.from({ length: 501 }, () => ({
          eventType: 'auth.success',
          observedAt: now(),
        })),
      },
    ];
    for (const body of bad) {
      expect((await ingest(s.token, body)).statusCode, JSON.stringify(body).slice(0, 90)).toBe(400);
    }
    expect((await s.admin.get('/api/telemetry-events')).json().items).toHaveLength(0);
  });

  it('refuses events for suspended integrations or without the ingest permission', async () => {
    const s = await setup();
    const integ = (await s.admin.get(`/api/integrations/${s.integrationId}`)).json().integration;
    await s.admin.post(`/api/integrations/${s.integrationId}/suspend`, { version: integ.version });
    const res = await ingest(s.token, {
      events: [{ eventType: 'auth.success', observedAt: now() }],
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('INTEGRATION_NOT_ACTIVE');

    const noPerm = await setup({ grantedPermissions: [] });
    const r2 = await ingest(noPerm.token, {
      events: [{ eventType: 'auth.success', observedAt: now() }],
    });
    expect(r2.statusCode).toBe(403);
    expect(r2.json().error.code).toBe('PERMISSION_NOT_GRANTED');
  });

  it('keeps telemetry inside the token’s tenant and immutable', async () => {
    const a = await setup();
    const b = await setup();
    await ingest(a.token, {
      events: [{ eventType: 'auth.success', observedAt: now(), sourceEventId: 'only-a' }],
    });
    expect((await b.admin.get('/api/telemetry-events')).json().items).toHaveLength(0);
    await expect(ctx.pool.query("UPDATE telemetry_events SET severity = 'LOW'")).rejects.toThrow(
      /permission denied/,
    );
    await expect(ctx.pool.query('DELETE FROM telemetry_events')).rejects.toThrow(
      /permission denied/,
    );
  });

  it('revokes ingest tokens when the integration is revoked', async () => {
    const s = await setup();
    const integ = (await s.admin.get(`/api/integrations/${s.integrationId}`)).json().integration;
    expect(
      (
        await s.admin.post(`/api/integrations/${s.integrationId}/revoke`, {
          version: integ.version,
        })
      ).statusCode,
    ).toBe(200);
    expect(
      (await ingest(s.token, { events: [{ eventType: 'auth.success', observedAt: now() }] }))
        .statusCode,
    ).toBe(401);
  });
});

describe('detection', () => {
  it('raises one brute-force finding with linked evidence, idempotently', async () => {
    const s = await setup();
    await ingest(s.token, { events: failures('198.51.100.9', 12) });
    await drain();
    const findings = (await s.admin.get('/api/findings?active=true')).json().items;
    const f = findings.find((x: { ruleId: string }) => x.ruleId === 'auth.brute_force');
    expect(f).toMatchObject({
      severity: 'HIGH',
      status: 'OPEN',
      assetId: s.assetId,
      groupKey: 'ip:198.51.100.9',
    });
    expect(f.occurrenceCount).toBe(12);
    const detail = (await s.admin.get(`/api/findings/${f.id}`)).json();
    expect(detail.evidence).toHaveLength(12);
    expect(detail.evidence[0]).toMatchObject({
      kind: 'OBSERVATION',
      probative: true,
      verificationStatus: 'NOT_RUN',
    });
    expect(detail.evidence[0].provenance.collectorId).toBe(s.integrationId);

    // A later batch from the same address updates the same finding.
    await ingest(s.token, { events: failures('198.51.100.9', 3, 'alice', 1) });
    await drain();
    const after = (await s.admin.get('/api/findings?active=true'))
      .json()
      .items.filter((x: { ruleId: string }) => x.ruleId === 'auth.brute_force');
    expect(after).toHaveLength(1);
    expect(after[0].occurrenceCount).toBeGreaterThan(12);
    expect(await auditEvents("action = 'finding.create' AND target_id = $1", [f.id])).toHaveLength(
      1,
    );
  });

  it('does not alert below the threshold', async () => {
    const s = await setup();
    await ingest(s.token, { events: failures('198.51.100.10', 9) });
    await drain();
    expect((await s.admin.get('/api/findings')).json().items).toHaveLength(0);
  });

  it('flags a successful sign-in after repeated failures as critical', async () => {
    const s = await setup();
    await ingest(s.token, {
      events: [
        ...failures('192.0.2.50', 6, 'carol'),
        {
          eventType: 'auth.success',
          observedAt: ago(1),
          actor: { ip: '192.0.2.50', userId: 'carol' },
          sourceEventId: `ok-${uid()}`,
        },
      ],
    });
    await drain();
    const f = (await s.admin.get('/api/findings'))
      .json()
      .items.find((x: { ruleId: string }) => x.ruleId === 'auth.success_after_failures');
    expect(f).toMatchObject({ severity: 'CRITICAL', groupKey: 'ip:192.0.2.50:user:carol' });
  });

  it('detects injection payloads but not benign requests', async () => {
    const s = await setup();
    const req = (path: string, ip: string) => ({
      eventType: 'http.request',
      observedAt: now(),
      actor: { ip },
      attributes: { path, method: 'GET' },
      sourceEventId: `r-${uid()}`,
    });
    await ingest(s.token, {
      events: [
        req("/items?id=1' OR '1'='1", '203.0.113.20'),
        req('/files/../../etc/passwd', '203.0.113.21'),
        req('/search?q=<script>alert(1)</script>', '203.0.113.22'),
        req('/products/42?sort=price', '203.0.113.23'),
      ],
    });
    await drain();
    const kinds = (await s.admin.get('/api/findings'))
      .json()
      .items.map((f: { groupKey: string }) => f.groupKey)
      .sort();
    expect(kinds).toEqual([
      'ip:203.0.113.20:sql_injection',
      'ip:203.0.113.21:path_traversal',
      'ip:203.0.113.22:cross_site_scripting',
    ]);
  });

  it('flags privileged role grants and high-severity source alerts', async () => {
    const s = await setup();
    await ingest(s.token, {
      events: [
        {
          eventType: 'iam.role_granted',
          observedAt: now(),
          actor: { userId: 'mallory' },
          attributes: { role: 'Admin', target_user: 'eve' },
        },
        {
          eventType: 'iam.role_granted',
          observedAt: now(),
          attributes: { role: 'viewer', target_user: 'dan' },
        },
        {
          eventType: 'security.alert',
          observedAt: now(),
          severity: 'CRITICAL',
          attributes: { alert_id: 'edr-77', name: 'Ransomware behaviour' },
        },
        {
          eventType: 'security.alert',
          observedAt: now(),
          severity: 'LOW',
          attributes: { alert_id: 'edr-78' },
        },
      ],
    });
    await drain();
    const items = (await s.admin.get('/api/findings')).json().items;
    expect(items.map((f: { ruleId: string }) => f.ruleId).sort()).toEqual([
      'iam.privileged_grant',
      'source.high_severity_alert',
    ]);
    expect(
      items.find((f: { ruleId: string }) => f.ruleId === 'source.high_severity_alert'),
    ).toMatchObject({
      severity: 'CRITICAL',
      title: 'Ransomware behaviour',
    });
  });

  it('uses only linear-time signature patterns (bounded input stays fast)', () => {
    const hostile = `${"'".repeat(256)}${'('.repeat(256)}`;
    const start = performance.now();
    for (const { re } of INJECTION_SIGNATURES) re.test(hostile);
    expect(performance.now() - start).toBeLessThan(50);
  });
});

describe('finding lifecycle', () => {
  async function withFinding() {
    const s = await setup();
    await ingest(s.token, { events: failures('198.51.100.30', 10) });
    await drain();
    const f = (await s.admin.get('/api/findings')).json().items[0];
    return { ...s, finding: f };
  }

  it('requires a note to close, validates transitions, and reopens cleanly', async () => {
    const { admin, finding } = await withFinding();
    const noNote = await admin.patch(`/api/findings/${finding.id}`, {
      version: finding.version,
      status: 'RESOLVED',
    });
    expect(noNote.statusCode).toBe(400);
    const triaged = (
      await admin.patch(`/api/findings/${finding.id}`, {
        version: finding.version,
        status: 'TRIAGED',
      })
    ).json();
    const resolved = await admin.patch(`/api/findings/${finding.id}`, {
      version: triaged.version,
      status: 'RESOLVED',
      resolutionNote: 'Source blocked at the edge.',
    });
    expect(resolved.json()).toMatchObject({
      status: 'RESOLVED',
      resolutionNote: 'Source blocked at the edge.',
    });
    const bad = await admin.patch(`/api/findings/${finding.id}`, {
      version: resolved.json().version,
      status: 'TRIAGED',
    });
    expect(bad.statusCode).toBe(409);
    expect(bad.json().error.code).toBe('INVALID_STATE_TRANSITION');
    const reopened = await admin.patch(`/api/findings/${finding.id}`, {
      version: resolved.json().version,
      status: 'OPEN',
    });
    expect(reopened.json()).toMatchObject({ status: 'OPEN', resolutionNote: null });
    const stale = await admin.patch(`/api/findings/${finding.id}`, {
      version: finding.version,
      status: 'TRIAGED',
    });
    expect(stale.statusCode).toBe(409);
    expect(
      await auditEvents("action = 'finding.update' AND target_id = $1", [finding.id]),
    ).toHaveLength(3);
  });

  it('opens a new finding when the activity recurs after resolution', async () => {
    const { admin, token, finding } = await withFinding();
    await admin.patch(`/api/findings/${finding.id}`, {
      version: finding.version,
      status: 'RESOLVED',
      resolutionNote: 'done',
    });
    await ingest(token, { events: failures('198.51.100.30', 10) });
    await drain();
    const items = (await admin.get('/api/findings')).json().items;
    expect(items).toHaveLength(2);
    expect(items.filter((f: { status: string }) => f.status === 'OPEN')).toHaveLength(1);
  });

  it('restricts risk acceptance to admins with recent reauthentication', async () => {
    const { tenantId, finding } = await withFinding();
    const op = await memberClient(ctx, 'SECURITY_OPERATOR', tenantId);
    const body = {
      version: finding.version,
      status: 'ACCEPTED_RISK',
      resolutionNote: 'Compensating control',
    };
    expect((await op.client.patch(`/api/findings/${finding.id}`, body)).statusCode).toBe(403);
    const sec = await memberClient(ctx, 'SECURITY_ADMIN', tenantId);
    await owner().query('UPDATE sessions SET reauthenticated_at = NULL WHERE principal_id = $1', [
      sec.user.id,
    ]);
    const stale = await sec.client.patch(`/api/findings/${finding.id}`, body);
    expect(stale.json().error.code).toBe('REAUTHENTICATION_REQUIRED');
    await sec.client.post('/api/auth/reauthenticate', { password: sec.user.password });
    expect((await sec.client.patch(`/api/findings/${finding.id}`, body)).json().status).toBe(
      'ACCEPTED_RISK',
    );
  });

  it('enforces roles, assignee membership, and tenant boundaries', async () => {
    const { admin, tenantId, finding } = await withFinding();
    const analyst = await memberClient(ctx, 'READ_ONLY_ANALYST', tenantId);
    expect((await analyst.client.get(`/api/findings/${finding.id}`)).statusCode).toBe(200);
    expect(
      (await analyst.client.patch(`/api/findings/${finding.id}`, { version: 1, status: 'TRIAGED' }))
        .statusCode,
    ).toBe(403);
    const outsider = await memberClient(ctx, 'TENANT_ADMIN');
    expect((await outsider.client.get(`/api/findings/${finding.id}`)).statusCode).toBe(404);
    expect(
      (
        await admin.patch(`/api/findings/${finding.id}`, {
          version: finding.version,
          assigneePrincipalId: outsider.user.id,
        })
      ).statusCode,
    ).toBe(400);
    expect(
      (
        await admin.patch(`/api/findings/${finding.id}`, {
          version: finding.version,
          assigneePrincipalId: analyst.user.id,
        })
      ).json().assigneePrincipalId,
    ).toBe(analyst.user.id);
  });
});

describe('evidence', () => {
  it('verifies observation integrity and detects tampering of the underlying event', async () => {
    const s = await setup();
    await ingest(s.token, { events: failures('198.51.100.40', 10) });
    await drain();
    const f = (await s.admin.get('/api/findings')).json().items[0];
    const ev = (await s.admin.get(`/api/findings/${f.id}`)).json().evidence[0];
    const ok = await s.admin.post(`/api/evidence/${ev.id}/verify`);
    expect(ok.json().verificationStatus).toBe('VERIFIED');

    const su = superuser();
    const { rows } = await su.query('SELECT attributes FROM telemetry_events WHERE id = $1', [
      ev.telemetryEventId,
    ]);
    try {
      await su.query(`UPDATE telemetry_events SET attributes = '{"forged": true}' WHERE id = $1`, [
        ev.telemetryEventId,
      ]);
      const tampered = await s.admin.post(`/api/evidence/${ev.id}/verify`);
      expect(tampered.json().verificationStatus).toBe('FAILED');
      expect(
        await auditEvents("action = 'evidence.verify' AND outcome = 'FAILURE' AND target_id = $1", [
          ev.id,
        ]),
      ).toHaveLength(1);
    } finally {
      await su.query('UPDATE telemetry_events SET attributes = $2 WHERE id = $1', [
        ev.telemetryEventId,
        rows[0].attributes,
      ]);
    }
  });

  it('keeps notes non-probative and evidence content immutable', async () => {
    const s = await setup();
    await ingest(s.token, { events: failures('198.51.100.41', 10) });
    await drain();
    const f = (await s.admin.get('/api/findings')).json().items[0];
    const note = (
      await s.admin.post(`/api/findings/${f.id}/notes`, { text: 'Looks like a password spray.' })
    ).json();
    expect(note).toMatchObject({
      kind: 'OPERATOR_NOTE',
      probative: false,
      verificationStatus: 'NOT_APPLICABLE',
    });
    expect((await s.admin.post(`/api/evidence/${note.id}/verify`)).statusCode).toBe(422);
    await expect(
      owner().query("UPDATE evidence SET verification_status = 'VERIFIED' WHERE id = $1", [
        note.id,
      ]),
    ).rejects.toThrow(/check constraint/);
    await expect(
      owner().query(`UPDATE evidence SET body = '{"text":"rewritten"}' WHERE id = $1`, [note.id]),
    ).rejects.toThrow(/immutable/);
  });
});

describe('investigations', () => {
  it('group findings, record notes, and lock when closed', async () => {
    const s = await setup();
    await ingest(s.token, { events: failures('198.51.100.50', 10) });
    await drain();
    const f = (await s.admin.get('/api/findings')).json().items[0];
    const other = await setup();
    const foreign = await ingest(other.token, { events: failures('198.51.100.51', 10) })
      .then(drain)
      .then(async () => (await other.admin.get('/api/findings')).json().items[0]);
    expect(
      (await s.admin.post('/api/investigations', { title: 'x', findingIds: [foreign.id] }))
        .statusCode,
    ).toBe(400);

    const inv = (
      await s.admin.post('/api/investigations', { title: 'Password spray', findingIds: [f.id] })
    ).json();
    expect(inv.findingIds).toEqual([f.id]);
    expect(
      (await s.admin.post(`/api/investigations/${inv.id}/notes`, { text: 'Blocked range.' }))
        .statusCode,
    ).toBe(201);
    const closed = (
      await s.admin.patch(`/api/investigations/${inv.id}`, {
        version: inv.version,
        status: 'CLOSED',
      })
    ).json();
    expect(closed.closedAt).not.toBeNull();
    expect(
      (await s.admin.post(`/api/investigations/${inv.id}/notes`, { text: 'late' })).statusCode,
    ).toBe(409);
    expect(
      (
        await s.admin.patch(`/api/investigations/${inv.id}`, {
          version: closed.version,
          title: 'edit',
        })
      ).statusCode,
    ).toBe(409);
    const detail = (await s.admin.get(`/api/investigations/${inv.id}`)).json();
    expect(detail.findings).toHaveLength(1);
    expect(detail.notes[0].kind).toBe('OPERATOR_NOTE');
    expect((await other.admin.get(`/api/investigations/${inv.id}`)).statusCode).toBe(404);
  });
});

describe('asset graph', () => {
  it('links assets within a tenant and returns a bounded neighbourhood', async () => {
    const s = await setup();
    const db = (await s.admin.post('/api/assets', validAsset({ assetType: 'DATABASE' }))).json();
    const rel = await s.admin.post('/api/asset-relationships', {
      fromAssetId: s.assetId,
      toAssetId: db.id,
      kind: 'STORES_DATA_IN',
    });
    expect(rel.statusCode).toBe(201);
    expect(
      (
        await s.admin.post('/api/asset-relationships', {
          fromAssetId: s.assetId,
          toAssetId: s.assetId,
          kind: 'DEPENDS_ON',
        })
      ).statusCode,
    ).toBe(400);
    const foreign = (
      await (await memberClient(ctx, 'TENANT_ADMIN')).client.post('/api/assets', validAsset())
    ).json();
    expect(
      (
        await s.admin.post('/api/asset-relationships', {
          fromAssetId: s.assetId,
          toAssetId: foreign.id,
          kind: 'DEPENDS_ON',
        })
      ).statusCode,
    ).toBe(400);

    await ingest(s.token, { events: failures('198.51.100.60', 10) });
    await drain();
    const graph = (await s.admin.get(`/api/graph?assetId=${db.id}&depth=1`)).json();
    const types = graph.nodes.map((n: { type: string }) => n.type).sort();
    expect(types).toEqual(['asset', 'asset', 'finding', 'integration']);
    expect(graph.edges.map((e: { kind: string }) => e.kind).sort()).toEqual([
      'AFFECTS',
      'OBSERVES',
      'STORES_DATA_IN',
    ]);
    expect((await s.admin.get(`/api/graph?assetId=${foreign.id}`)).statusCode).toBe(404);
  });
});

describe('coverage', () => {
  const freshness = 3600_000;
  const sig = (o: Partial<Parameters<typeof computeCoverage>[0]['integrations'][number]> = {}) => ({
    name: 'i',
    status: 'CONNECTED' as const,
    lastHealthStatus: 'CONNECTED',
    lastHealthAt: new Date(),
    lastEventAt: null,
    collectsEvents: false,
    ...o,
  });
  const state = (integrations: ReturnType<typeof sig>[], scopeExpiresAt: string | null = null) =>
    computeCoverage({ scopeExpiresAt, integrations }, freshness).state;

  it('follows the documented decision order', () => {
    expect(state([], '2000-01-01T00:00:00Z')).toBe('VERIFICATION_REQUIRED');
    expect(state([])).toBe('UNKNOWN');
    expect(state([sig({ status: 'SUSPENDED' })])).toBe('UNKNOWN');
    expect(state([sig({ lastHealthStatus: 'DISCONNECTED' })])).toBe('DISCONNECTED');
    expect(state([sig(), sig({ lastHealthStatus: 'DEGRADED' })])).toBe('DEGRADED');
    expect(state([sig({ lastHealthAt: new Date(Date.now() - 2 * freshness) })])).toBe('STALE');
    expect(state([sig()])).toBe('PARTIALLY_COVERED');
    expect(state([sig({ collectsEvents: true, lastEventAt: new Date() })])).toBe(
      'VERIFIED_WITHIN_DEFINED_SCOPE',
    );
    expect(
      state([sig({ collectsEvents: true, lastEventAt: new Date(Date.now() - 2 * freshness) })]),
    ).toBe('PARTIALLY_COVERED');
  });

  it('is computed from live signals through the API', async () => {
    const s = await setup();
    const bare = (await s.admin.post('/api/assets', validAsset())).json();
    expect(bare.coverageState).toBe('UNKNOWN');
    const before = (await s.admin.get(`/api/assets/${s.assetId}`)).json();
    expect(before.coverageState).toBe('STALE');
    await ingest(s.token, { events: [{ eventType: 'auth.success', observedAt: now() }] });
    const after = (await s.admin.get(`/api/assets/${s.assetId}`)).json();
    expect(after.coverageState).toBe('VERIFIED_WITHIN_DEFINED_SCOPE');
    const list = (await s.admin.get('/api/coverage')).json().items;
    expect(list.find((c: { assetId: string }) => c.assetId === bare.id).reasons[0]).toMatch(
      /No active integration/,
    );
    const overview = (await s.admin.get('/api/overview')).json();
    expect(overview.telemetry.state).toBe('OPERATIONAL');
    expect(overview.assets.byCoverage.VERIFIED_WITHIN_DEFINED_SCOPE).toBe(1);
  });
});

describe('ingest limits', () => {
  it('rate-limits per token and bounds request size', async () => {
    const limited = await createTestApp({
      INGEST_RATE_LIMIT_PER_MINUTE: '2',
      INGEST_BODY_LIMIT_BYTES: '4096',
    });
    try {
      const s = await setup();
      const send = (body: unknown) =>
        limited.app.inject({
          method: 'POST',
          url: '/ingest/v1/events',
          headers: { 'content-type': 'application/json', authorization: `Bearer ${s.token}` },
          payload: JSON.stringify(body),
        });
      const big = {
        events: Array.from({ length: 50 }, () => ({
          eventType: 'auth.success',
          observedAt: now(),
          attributes: { a: 'x'.repeat(100) },
        })),
      };
      expect((await send(big)).statusCode).toBe(413);
      const small = { events: [{ eventType: 'auth.success', observedAt: now() }] };
      const codes = [(await send(small)).statusCode, (await send(small)).statusCode];
      expect(codes).toContain(429);
    } finally {
      await limited.close();
    }
  });
});
