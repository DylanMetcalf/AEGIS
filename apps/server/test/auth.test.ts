import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sha256 } from '../src/security/tokens.js';
import {
  PASSWORD,
  addMember,
  auditEvents,
  createTenant,
  createTestApp,
  createUser,
  httpClient,
  loginAs,
  owner,
  resetThrottle,
  type TestContext,
} from './helpers.js';

let ctx: TestContext;
beforeAll(async () => {
  ctx = await createTestApp({ LOGIN_MAX_FAILURES: '3' });
});
afterAll(async () => ctx.close());
beforeEach(resetThrottle);

describe('login', () => {
  it('authenticates valid credentials and sets a hardened session cookie', async () => {
    const user = await createUser();
    const client = httpClient(ctx.app);
    const res = await client.post('/api/auth/login', { email: user.email, password: PASSWORD });
    expect(res.statusCode).toBe(200);
    const cookie = res.cookies.find((c) => c.name === 'aegis_session')!;
    expect(cookie.httpOnly).toBe(true);
    expect(cookie.sameSite).toBe('Strict');
    expect(cookie.path).toBe('/');
    expect(cookie.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(res.body).not.toContain(cookie.value);

    const session = await client.get('/api/session');
    expect(session.statusCode).toBe(200);
    expect(session.json().principal.email).toBe(user.email);
  });

  it('stores only a hash of the session token', async () => {
    const user = await createUser();
    const client = await loginAs(ctx.app, user);
    const { rows } = await owner().query('SELECT token_hash FROM sessions WHERE principal_id = $1', [user.id]);
    expect(rows).toHaveLength(1);
    expect(Buffer.compare(rows[0].token_hash, sha256(client.cookie!))).toBe(0);
    const { rows: leak } = await owner().query(
      "SELECT 1 FROM sessions WHERE encode(token_hash, 'escape') LIKE '%' || $1 || '%'",
      [client.cookie],
    );
    expect(leak).toHaveLength(0);
  });

  it('returns the same generic error for a wrong password, an unknown account, and a disabled account', async () => {
    const user = await createUser();
    const disabled = await createUser({ status: 'DISABLED' });
    const client = httpClient(ctx.app);
    const wrong = await client.post('/api/auth/login', { email: user.email, password: 'wrong password!!' });
    const unknown = await client.post('/api/auth/login', { email: 'nobody@example.test', password: PASSWORD });
    const off = await client.post('/api/auth/login', { email: disabled.email, password: PASSWORD });
    for (const r of [wrong, unknown, off]) {
      expect(r.statusCode).toBe(401);
      expect(r.json().error.code).toBe('INVALID_CREDENTIALS');
      expect(r.json().error.message).toBe('Invalid email or password');
      expect(r.cookies.find((c) => c.name === 'aegis_session')).toBeUndefined();
    }
  });

  it('locks an account after repeated failures, identically for unknown accounts', async () => {
    const user = await createUser();
    const client = httpClient(ctx.app);
    for (let i = 0; i < 3; i++) {
      await client.post('/api/auth/login', { email: user.email, password: 'wrong password!!' });
      await client.post('/api/auth/login', { email: 'ghost@example.test', password: 'wrong password!!' });
    }
    const locked = await client.post('/api/auth/login', { email: user.email, password: PASSWORD });
    const ghost = await client.post('/api/auth/login', { email: 'ghost@example.test', password: PASSWORD });
    expect(locked.statusCode).toBe(429);
    expect(ghost.statusCode).toBe(429);
    expect(locked.json().error.code).toBe(ghost.json().error.code);
    const denied = await auditEvents("action = 'auth.login' AND reason_code = 'THROTTLED'", []);
    expect(denied.length).toBeGreaterThan(0);
  });

  it('records failed logins in the audit log without the attempted password', async () => {
    const user = await createUser();
    await httpClient(ctx.app).post('/api/auth/login', { email: user.email, password: 'hunter2-attempt-xyz' });
    const events = await auditEvents("action = 'auth.login' AND target_id = $1", [user.id]);
    expect(events.at(-1)!.outcome).toBe('DENIED');
    expect(JSON.stringify(events)).not.toContain('hunter2-attempt-xyz');
  });

  it('rejects malformed and oversized login payloads', async () => {
    const client = httpClient(ctx.app);
    expect((await client.post('/api/auth/login', { email: 'not-an-email', password: 'x' })).statusCode).toBe(400);
    expect((await client.post('/api/auth/login', { email: 'a@b.test', password: 'x'.repeat(300) })).statusCode).toBe(400);
    expect((await client.post('/api/auth/login', { email: 'a@b.test', password: 'x', extra: 1 })).statusCode).toBe(400);
  });

  it('supersedes an existing session on login (no session fixation)', async () => {
    const user = await createUser();
    const client = await loginAs(ctx.app, user);
    const first = client.cookie!;
    await client.post('/api/auth/login', { email: user.email, password: PASSWORD });
    expect(client.cookie).not.toBe(first);
    const stale = httpClient(ctx.app);
    stale.cookie = first;
    expect((await stale.get('/api/session')).statusCode).toBe(401);
  });

  it('selects the only tenant automatically', async () => {
    const tenantId = await createTenant();
    const user = await createUser();
    await addMember(tenantId, user.id, 'AUDITOR');
    const client = await loginAs(ctx.app, user);
    expect((await client.get('/api/session')).json().activeTenant.id).toBe(tenantId);
  });
});

describe('session lifecycle', () => {
  it('logout invalidates the session server-side', async () => {
    const user = await createUser();
    const client = await loginAs(ctx.app, user);
    const token = client.cookie!;
    expect((await client.post('/api/auth/logout')).statusCode).toBe(204);
    const replay = httpClient(ctx.app);
    replay.cookie = token;
    expect((await replay.get('/api/session')).statusCode).toBe(401);
  });

  it('logout-all revokes every session of the principal', async () => {
    const user = await createUser();
    const a = await loginAs(ctx.app, user);
    const b = await loginAs(ctx.app, user);
    expect((await a.post('/api/auth/logout-all')).json().sessionsRevoked).toBe(2);
    expect((await b.get('/api/session')).statusCode).toBe(401);
  });

  it('expires idle sessions', async () => {
    const user = await createUser();
    const client = await loginAs(ctx.app, user);
    await owner().query(
      "UPDATE sessions SET last_seen_at = now() - interval '2 hours' WHERE principal_id = $1",
      [user.id],
    );
    expect((await client.get('/api/session')).statusCode).toBe(401);
  });

  it('expires sessions at their absolute lifetime', async () => {
    const user = await createUser();
    const client = await loginAs(ctx.app, user);
    await owner().query(
      "UPDATE sessions SET created_at = now() - interval '2 days', expires_at = now() - interval '1 second' WHERE principal_id = $1",
      [user.id],
    );
    expect((await client.get('/api/session')).statusCode).toBe(401);
  });

  it('invalidates sessions of a disabled principal immediately', async () => {
    const user = await createUser();
    const client = await loginAs(ctx.app, user);
    await owner().query("UPDATE principals SET status = 'DISABLED' WHERE id = $1", [user.id]);
    expect((await client.get('/api/session')).statusCode).toBe(401);
  });

  it('rejects forged and malformed session cookies', async () => {
    const client = httpClient(ctx.app);
    for (const forged of ['x', 'A'.repeat(43), '../../etc/passwd', '']) {
      client.cookie = forged;
      expect((await client.get('/api/session')).statusCode).toBe(401);
    }
  });

  it('lets a user list and revoke only their own sessions', async () => {
    const alice = await createUser();
    const bob = await createUser();
    const a1 = await loginAs(ctx.app, alice);
    const a2 = await loginAs(ctx.app, alice);
    const b = await loginAs(ctx.app, bob);
    const list = (await a1.get('/api/sessions')).json().items;
    expect(list).toHaveLength(2);
    const other = list.find((s: { current: boolean }) => !s.current);
    const bobSessions = (await b.get('/api/sessions')).json().items;
    expect((await a1.delete(`/api/sessions/${bobSessions[0].id}`)).statusCode).toBe(404);
    expect((await a1.delete(`/api/sessions/${other.id}`)).statusCode).toBe(204);
    expect((await a2.get('/api/session')).statusCode).toBe(401);
    expect((await b.get('/api/session')).statusCode).toBe(200);
  });
});

describe('password change and reauthentication', () => {
  it('requires the current password and revokes other sessions', async () => {
    const user = await createUser({ password: 'original-password-123' });
    const a = await loginAs(ctx.app, user);
    const b = await loginAs(ctx.app, user);
    const bad = await a.post('/api/auth/password', {
      currentPassword: 'not-the-password',
      newPassword: 'brand-new-password-456',
    });
    expect(bad.statusCode).toBe(401);
    const weak = await a.post('/api/auth/password', { currentPassword: 'original-password-123', newPassword: 'short' });
    expect(weak.statusCode).toBe(400);
    const ok = await a.post('/api/auth/password', {
      currentPassword: 'original-password-123',
      newPassword: 'brand-new-password-456',
    });
    expect(ok.statusCode).toBe(200);
    expect(ok.json().otherSessionsRevoked).toBe(1);
    expect((await b.get('/api/session')).statusCode).toBe(401);
    expect((await a.get('/api/session')).statusCode).toBe(200);
    const relog = httpClient(ctx.app);
    expect((await relog.post('/api/auth/login', { email: user.email, password: 'original-password-123' })).statusCode).toBe(401);
    expect((await relog.post('/api/auth/login', { email: user.email, password: 'brand-new-password-456' })).statusCode).toBe(200);
  });

  it('reauthentication requires the correct password and extends the window', async () => {
    const user = await createUser();
    const client = await loginAs(ctx.app, user);
    await owner().query('UPDATE sessions SET reauthenticated_at = NULL WHERE principal_id = $1', [user.id]);
    expect((await client.get('/api/session')).json().session.reauthenticatedUntil).toBeNull();
    expect((await client.post('/api/auth/reauthenticate', { password: 'wrong-password' })).statusCode).toBe(401);
    const ok = await client.post('/api/auth/reauthenticate', { password: PASSWORD });
    expect(ok.statusCode).toBe(200);
    expect(Date.parse(ok.json().reauthenticatedUntil)).toBeGreaterThan(Date.now());
  });
});

describe('cross-site request protection', () => {
  it('rejects state-changing requests without the application origin', async () => {
    const user = await createUser();
    const client = await loginAs(ctx.app, user);
    const noOrigin = await ctx.app.inject({
      method: 'POST',
      url: '/api/auth/logout-all',
      headers: { cookie: `aegis_session=${client.cookie}` },
    });
    expect(noOrigin.statusCode).toBe(403);
    expect(noOrigin.json().error.code).toBe('ORIGIN_REJECTED');
    const evil = await client.post('/api/auth/logout-all', undefined, { origin: 'https://evil.example' });
    expect(evil.statusCode).toBe(403);
    expect((await client.get('/api/session')).statusCode).toBe(200);
  });

  it('rejects non-JSON bodies, including cross-site form encodings', async () => {
    for (const type of ['text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data; boundary=x']) {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/api/auth/login',
        headers: { origin: 'http://localhost:5173', 'content-type': type },
        payload: 'email=a@b.test&password=x',
      });
      expect(res.statusCode).toBe(415);
    }
  });

  it('rate-limits credential endpoints per client', async () => {
    const limited = await createTestApp({ LOGIN_RATE_LIMIT_PER_MINUTE: '3' });
    try {
      const client = httpClient(limited.app);
      const codes: number[] = [];
      for (let i = 0; i < 5; i++) {
        codes.push((await client.post('/api/auth/login', { email: 'x@y.test', password: 'whatever' })).statusCode);
      }
      expect(codes.slice(0, 3)).toEqual([401, 401, 401]);
      expect(codes.slice(3)).toEqual([429, 429]);
    } finally {
      await limited.close();
    }
  });

  it('requires authentication for protected routes', async () => {
    const anon = httpClient(ctx.app);
    for (const url of ['/api/session', '/api/assets', '/api/integrations', '/api/audit-events', '/api/overview']) {
      const res = await anon.get(url);
      expect(res.statusCode, url).toBe(401);
      expect(res.json().error.code).toBe('UNAUTHENTICATED');
    }
  });
});
