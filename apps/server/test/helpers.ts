import { randomBytes } from 'node:crypto';
import { Writable } from 'node:stream';
import type { PlatformRole, PrincipalKind, TenantRole } from '@aegis/shared';
import type { LightMyRequestResponse } from 'fastify';
import pg from 'pg';
import { inject } from 'vitest';
import { loadConfig, type AppConfig } from '../src/config.js';
import { createPool, type Pool } from '../src/db/pool.js';
import { buildApp, type App } from '../src/http/app.js';
import { createProviderRegistry } from '../src/integrations/registry.js';
import { healthCheckJobHandler } from '../src/jobs/health-check-job.js';
import { Worker } from '../src/jobs/worker.js';
import { hashPassword } from '../src/security/passwords.js';

export const ORIGIN = 'http://localhost:5173';

export function testEnv(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    AEGIS_ENV: 'test',
    APP_ORIGIN: ORIGIN,
    DATABASE_URL: inject('db').appUrl,
    SESSION_COOKIE_SECURE: 'false',
    LOG_LEVEL: 'silent',
    WORKER_ENABLED: 'false',
    INTEGRATION_TEST_ADAPTER_ENABLED: 'true',
    RATE_LIMIT_PER_MINUTE: '10000',
    LOGIN_RATE_LIMIT_PER_MINUTE: '10000',
    ...overrides,
  };
}

export function testConfig(overrides: Record<string, string> = {}): AppConfig {
  return loadConfig(testEnv(overrides));
}

/** Owner connection for fixtures and tamper tests. Bypasses RLS (table owner). */
let ownerPool: pg.Pool | null = null;
export function owner(): pg.Pool {
  ownerPool ??= new pg.Pool({ connectionString: inject('db').ownerUrl, max: 3 });
  return ownerPool;
}

let adminPool: pg.Pool | null = null;
/** Superuser connection: used only to simulate a privileged attacker. */
export function superuser(): pg.Pool {
  adminPool ??= new pg.Pool({ connectionString: inject('db').adminUrl, max: 2 });
  return adminPool;
}

export interface TestContext {
  app: App;
  pool: Pool;
  config: AppConfig;
  logs: string[];
  close(): Promise<void>;
}

export async function createTestApp(overrides: Record<string, string> = {}): Promise<TestContext> {
  const config = testConfig(overrides);
  const pool = createPool({ url: config.database.url, max: 10, statementTimeoutMs: 10000 });
  const providers = createProviderRegistry({
    testAdapterEnabled: config.integrations.testAdapterEnabled,
  });
  const logs: string[] = [];
  const logStream = new Writable({
    write(chunk, _enc, cb) {
      logs.push(String(chunk));
      cb();
    },
  });
  const app = await buildApp({ config, pool, providers, logStream });
  await app.ready();
  return {
    app,
    pool,
    config,
    logs,
    async close() {
      await app.close();
      await pool.end();
    },
  };
}

export function createTestWorker(ctx: TestContext, env?: NodeJS.ProcessEnv): Worker {
  const providers = createProviderRegistry({ testAdapterEnabled: true });
  return new Worker({ pool: ctx.pool, config: ctx.config, log: ctx.app.log }, [
    healthCheckJobHandler({ config: ctx.config, providers, env }),
  ]);
}

export const uid = () => randomBytes(5).toString('hex');

/** Shared password hash so fixtures stay fast (argon2 is deliberately slow). */
export const PASSWORD = 'correct horse battery staple';
let passwordHash: Promise<string> | null = null;

export async function createUser(
  opts: {
    email?: string;
    password?: string;
    platformRole?: PlatformRole | null;
    kind?: PrincipalKind;
    status?: 'ACTIVE' | 'DISABLED';
  } = {},
): Promise<{ id: string; email: string; password: string }> {
  const kind = opts.kind ?? 'HUMAN';
  const email = opts.email ?? `user-${uid()}@example.test`;
  const password = opts.password ?? PASSWORD;
  const hash =
    kind !== 'HUMAN'
      ? null
      : opts.password
        ? await hashPassword(opts.password)
        : await (passwordHash ??= hashPassword(PASSWORD));
  const { rows } = await owner().query<{ id: string }>(
    `INSERT INTO principals (kind, email, display_name, password_hash, platform_role, status)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
    [
      kind,
      kind === 'HUMAN' ? email : null,
      `Test ${kind}`,
      hash,
      opts.platformRole ?? null,
      opts.status ?? 'ACTIVE',
    ],
  );
  return { id: rows[0]!.id, email, password };
}

export async function createTenant(slug = `t-${uid()}`): Promise<string> {
  const { rows } = await owner().query<{ id: string }>(
    'INSERT INTO tenants (slug, display_name) VALUES ($1, $2) RETURNING id',
    [slug, `Tenant ${slug}`],
  );
  return rows[0]!.id;
}

export async function addMember(
  tenantId: string,
  principalId: string,
  role: TenantRole,
  status: 'ACTIVE' | 'SUSPENDED' | 'REMOVED' = 'ACTIVE',
): Promise<string> {
  const { rows } = await owner().query<{ id: string }>(
    'INSERT INTO memberships (tenant_id, principal_id, role, status) VALUES ($1, $2, $3, $4) RETURNING id',
    [tenantId, principalId, role, status],
  );
  return rows[0]!.id;
}

export async function resetThrottle(): Promise<void> {
  await owner().query('DELETE FROM auth_throttle');
}

type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface HttpClient {
  cookie: string | null;
  request(
    method: Method,
    url: string,
    body?: unknown,
    headers?: Record<string, string>,
  ): Promise<LightMyRequestResponse>;
  get(url: string): Promise<LightMyRequestResponse>;
  post(
    url: string,
    body?: unknown,
    headers?: Record<string, string>,
  ): Promise<LightMyRequestResponse>;
  put(url: string, body?: unknown): Promise<LightMyRequestResponse>;
  patch(url: string, body?: unknown): Promise<LightMyRequestResponse>;
  delete(url: string): Promise<LightMyRequestResponse>;
}

/** A browser-like client: sends the app Origin and keeps the session cookie. */
export function httpClient(app: App, cookieName = 'aegis_session'): HttpClient {
  const client: HttpClient = {
    cookie: null,
    async request(method, url, body, headers = {}) {
      const res = await app.inject({
        method,
        url,
        headers: {
          origin: ORIGIN,
          ...(client.cookie ? { cookie: `${cookieName}=${client.cookie}` } : {}),
          ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
          ...headers,
        },
        ...(body !== undefined ? { payload: JSON.stringify(body) } : {}),
      });
      const set = res.cookies.find((c) => c.name === cookieName);
      if (set) client.cookie = set.value || null;
      return res;
    },
    get: (url) => client.request('GET', url),
    post: (url, body, headers) => client.request('POST', url, body, headers),
    put: (url, body) => client.request('PUT', url, body),
    patch: (url, body) => client.request('PATCH', url, body),
    delete: (url) => client.request('DELETE', url),
  };
  return client;
}

export async function loginAs(
  app: App,
  user: { email: string; password: string },
  tenantId?: string,
): Promise<HttpClient> {
  const client = httpClient(app);
  const res = await client.post('/api/auth/login', { email: user.email, password: user.password });
  if (res.statusCode !== 200) throw new Error(`login failed: ${res.statusCode} ${res.body}`);
  if (tenantId) {
    const sel = await client.put('/api/session/tenant', { tenantId });
    if (sel.statusCode !== 204)
      throw new Error(`tenant select failed: ${sel.statusCode} ${sel.body}`);
  }
  return client;
}

/** Create a tenant with a member of the given role and return a logged-in client. */
export async function memberClient(
  ctx: TestContext,
  role: TenantRole,
  tenantId?: string,
): Promise<{
  client: HttpClient;
  tenantId: string;
  user: { id: string; email: string; password: string };
}> {
  const t = tenantId ?? (await createTenant());
  const user = await createUser();
  await addMember(t, user.id, role);
  const client = await loginAs(ctx.app, user, t);
  return { client, tenantId: t, user };
}

export function validAsset(overrides: Record<string, unknown> = {}) {
  return {
    name: `Asset ${uid()}`,
    assetType: 'API',
    environment: 'STAGING',
    criticality: 'MEDIUM',
    description: 'Test asset',
    authorizationScope: {
      statement: 'The owner authorizes AEGIS to monitor this API.',
      identifiers: ['api.example.test'],
      authorizedBy: 'Asset Owner',
      authorizedAt: '2026-01-01T00:00:00Z',
    },
    ...overrides,
  };
}

export async function auditEvents(
  where: string,
  params: unknown[],
): Promise<Record<string, unknown>[]> {
  const { rows } = await owner().query(
    `SELECT * FROM audit_events WHERE ${where} ORDER BY chain_position`,
    params,
  );
  return rows;
}
