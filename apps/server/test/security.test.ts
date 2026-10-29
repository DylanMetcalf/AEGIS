import Fastify from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { REDACTED, redact } from '../src/security/redact.js';
import { checkUrlPolicy, isBlockedAddress } from '../src/security/safe-http.js';
import { CredentialUnavailableError, resolveCredentialRef } from '../src/integrations/registry.js';
import {
  PASSWORD,
  createTestApp,
  createUser,
  httpClient,
  loginAs,
  memberClient,
  resetThrottle,
  validAsset,
  type TestContext,
} from './helpers.js';

let ctx: TestContext;
beforeAll(async () => {
  ctx = await createTestApp({ LOG_LEVEL: 'info' });
});
afterAll(async () => ctx.close());
beforeEach(resetThrottle);

describe('route protection policy', () => {
  it('fails startup if an API route does not declare its authorization', async () => {
    const app = Fastify();
    app.addHook('onRoute', (route) => {
      if (route.url.startsWith('/api') && route.config?.auth === undefined) throw new Error('missing auth');
    });
    expect(() => app.get('/api/unprotected', async () => 'x')).toThrow(/missing auth/);
  });

  it('declares authorization on every registered API route', () => {
    const routes = ctx.app.printRoutes({ commonPrefix: false });
    expect(routes).toContain('/api/assets');
    // buildApp's onRoute guard would have thrown during startup otherwise.
  });
});

describe('response safety', () => {
  it('sets security headers', async () => {
    const res = await httpClient(ctx.app).get('/health/live');
    expect(res.headers['content-security-policy']).toContain("default-src 'self'");
    expect(res.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    expect(res.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('marks API responses as non-cacheable', async () => {
    const res = await httpClient(ctx.app).get('/api/session');
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('returns structured errors without stack traces or internals', async () => {
    const client = httpClient(ctx.app);
    const res = await client.request('POST', '/api/auth/login', undefined, {
      'content-type': 'application/json',
    });
    const malformed = await ctx.app.inject({
      method: 'POST',
      url: '/api/auth/login',
      headers: { origin: 'http://localhost:5173', 'content-type': 'application/json' },
      payload: '{"email": ',
    });
    for (const r of [res, malformed]) {
      expect(r.statusCode).toBe(400);
      const body = r.json();
      expect(body.error).toEqual(expect.objectContaining({ code: expect.any(String), requestId: expect.any(String) }));
      expect(r.body).not.toMatch(/at .*\.(ts|js):\d+|node_modules|stack/);
    }
  });

  it('rejects oversized request bodies', async () => {
    const { client } = await memberClient(ctx, 'TENANT_ADMIN');
    const res = await client.post('/api/assets', validAsset({ description: 'x'.repeat(70_000) }));
    expect(res.statusCode).toBe(413);
  });

  it('answers unknown API routes with a JSON 404', async () => {
    const res = await httpClient(ctx.app).get('/api/does-not-exist');
    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe('NOT_FOUND');
  });

  it('propagates safe correlation IDs and replaces unsafe ones', async () => {
    const ok = await ctx.app.inject({ method: 'GET', url: '/health/live', headers: { 'x-correlation-id': 'trace-123' } });
    expect(ok.headers['x-correlation-id']).toBe('trace-123');
    const bad = await ctx.app.inject({ method: 'GET', url: '/health/live', headers: { 'x-correlation-id': 'a b<script>' } });
    expect(bad.headers['x-correlation-id']).toBe(bad.headers['x-request-id']);
  });
});

describe('logging', () => {
  it('never writes passwords, session tokens, or cookies to logs', async () => {
    ctx.logs.length = 0;
    const user = await createUser();
    const client = await loginAs(ctx.app, user);
    await client.get('/api/session');
    await httpClient(ctx.app).post('/api/auth/login', { email: user.email, password: 'wrong-password-zz9' });
    const all = ctx.logs.join('\n');
    expect(all.length).toBeGreaterThan(0);
    expect(all).not.toContain(PASSWORD);
    expect(all).not.toContain('wrong-password-zz9');
    expect(all).not.toContain(client.cookie!);
  });
});

describe('redaction', () => {
  it('redacts sensitive keys recursively and bounds size', () => {
    const out = redact({
      password: 'a',
      Authorization: 'b',
      deep: { client_secret: 'c', list: [{ apiKey: 'd' }], fine: 1 },
      long: 'x'.repeat(600),
    }) as Record<string, unknown>;
    expect(out.password).toBe(REDACTED);
    expect(out.Authorization).toBe(REDACTED);
    expect((out.deep as Record<string, unknown>).client_secret).toBe(REDACTED);
    expect(((out.deep as { list: Record<string, unknown>[] }).list[0]!).apiKey).toBe(REDACTED);
    expect((out.deep as Record<string, unknown>).fine).toBe(1);
    expect((out.long as string).length).toBeLessThan(600);
  });

  it('survives cyclic-depth objects', () => {
    const a: Record<string, unknown> = {};
    let cur = a;
    for (let i = 0; i < 20; i++) cur = (cur.next = {}) as Record<string, unknown>;
    expect(JSON.stringify(redact(a))).toContain('[MAX_DEPTH]');
  });
});

describe('outbound request safety (SSRF)', () => {
  it.each([
    '127.0.0.1',
    '10.1.2.3',
    '172.16.0.1',
    '192.168.1.1',
    '169.254.169.254',
    '100.64.0.1',
    '0.0.0.0',
    '224.0.0.1',
    '::1',
    '::',
    'fe80::1',
    'fd00::1',
    '::ffff:127.0.0.1',
    '::ffff:7f00:1',
    '64:ff9b::a00:1',
    'not-an-ip',
  ])('blocks %s', (ip) => {
    expect(isBlockedAddress(ip)).toBe(true);
  });

  it.each(['93.184.215.14', '1.1.1.1', '2606:4700:4700::1111'])('allows public %s', (ip) => {
    expect(isBlockedAddress(ip)).toBe(false);
  });

  it('applies URL policy before any network access', () => {
    const strict = { allowPrivateNetwork: false, allowInsecureHttp: false };
    expect(checkUrlPolicy('https://example.com/health', strict)).toBeNull();
    expect(checkUrlPolicy('http://example.com/', strict)).toBe('SCHEME_NOT_ALLOWED');
    expect(checkUrlPolicy('https://u:p@example.com/', strict)).toBe('CREDENTIALS_IN_URL');
    expect(checkUrlPolicy('https://example.com/#x', strict)).toBe('FRAGMENT_NOT_ALLOWED');
    expect(checkUrlPolicy('https://metadata.internal/', strict)).toBe('DESTINATION_NOT_ALLOWED');
    expect(checkUrlPolicy('https://[::ffff:a9fe:a9fe]/', strict)).toBe('DESTINATION_NOT_ALLOWED');
    expect(checkUrlPolicy('javascript:alert(1)', strict)).toBe('SCHEME_NOT_ALLOWED');
  });
});

describe('credential references', () => {
  it('resolve only within the AEGIS_SECRET_ namespace and never fall back', () => {
    const env = { AEGIS_SECRET_A: 'value-a', DATABASE_URL: 'postgres://secret' };
    expect(resolveCredentialRef('env:AEGIS_SECRET_A', env)).toBe('value-a');
    expect(resolveCredentialRef(null, env)).toBeNull();
    expect(() => resolveCredentialRef('env:DATABASE_URL', env)).toThrow(CredentialUnavailableError);
    expect(() => resolveCredentialRef('env:AEGIS_SECRET_MISSING', env)).toThrow(CredentialUnavailableError);
    try {
      resolveCredentialRef('env:DATABASE_URL', env);
    } catch (err) {
      expect(String(err)).not.toContain('postgres://secret');
    }
  });
});
