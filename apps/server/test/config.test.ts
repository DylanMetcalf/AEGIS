import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from '../src/config.js';

const base = {
  AEGIS_ENV: 'development',
  APP_ORIGIN: 'http://localhost:5173',
  DATABASE_URL: 'postgres://app:pw@localhost:5432/aegis',
};

const prod = {
  AEGIS_ENV: 'production',
  APP_ORIGIN: 'https://aegis.example.com',
  DATABASE_URL: 'postgres://app:super-secret-pw@db.internal:5432/aegis?sslmode=verify-full', // secret-scan:allow fake value for redaction test
};

function issues(env: Record<string, string>): string[] {
  try {
    loadConfig(env);
    return [];
  } catch (err) {
    if (err instanceof ConfigError) return err.issues;
    throw err;
  }
}

describe('configuration', () => {
  it('loads with secure defaults', () => {
    const c = loadConfig(base);
    expect(c.session.cookieSecure).toBe(true);
    expect(c.session.cookieName).toBe('__Host-aegis_session');
    expect(c.integrations).toEqual({
      allowPrivateNetwork: false,
      allowInsecureHttp: false,
      testAdapterEnabled: false,
    });
  });

  it('fails when required values are missing or invalid', () => {
    expect(issues({})).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/^AEGIS_ENV/),
        expect.stringMatching(/^APP_ORIGIN/),
        expect.stringMatching(/^DATABASE_URL/),
      ]),
    );
    expect(issues({ ...base, AEGIS_ENV: 'prod' })[0]).toMatch(/AEGIS_ENV: Expected one of/);
    expect(issues({ ...base, PORT: '99999' })[0]).toMatch(/^PORT/);
    expect(issues({ ...base, APP_ORIGIN: 'http://localhost:5173/app' })[0]).toMatch(/^APP_ORIGIN/);
    expect(issues({ ...base, DATABASE_URL: 'mysql://x' })[0]).toMatch(/^DATABASE_URL/);
  });

  it('never includes values in error messages', () => {
    const msgs = issues({
      ...prod,
      DATABASE_URL: 'postgres://app:super-secret-pw@db.internal:5432/aegis', // secret-scan:allow fake value for redaction test
    }).join('\n');
    expect(msgs).toMatch(/DATABASE_URL/);
    expect(msgs).not.toContain('super-secret-pw');
    const enumMsg = issues({ ...base, LOG_LEVEL: 'leaky-value-123' }).join('\n');
    expect(enumMsg).not.toContain('leaky-value-123');
  });

  it('accepts a hardened production configuration', () => {
    expect(issues(prod)).toEqual([]);
  });

  it.each([
    ['SESSION_COOKIE_SECURE', 'false'],
    ['INTEGRATION_ALLOW_PRIVATE_NETWORK', 'true'],
    ['INTEGRATION_ALLOW_INSECURE_HTTP', 'true'],
    ['INTEGRATION_TEST_ADAPTER_ENABLED', 'true'],
    ['LOG_LEVEL', 'debug'],
  ])('rejects %s=%s outside development', (key, value) => {
    expect(issues({ ...prod, [key]: value })[0]).toMatch(new RegExp(`^${key}`));
    expect(issues({ ...prod, AEGIS_ENV: 'staging', [key]: value })[0]).toMatch(
      new RegExp(`^${key}`),
    );
    expect(issues({ ...base, [key]: value })).toEqual([]);
  });

  it('requires https origins and TLS database connections in production', () => {
    expect(issues({ ...prod, APP_ORIGIN: 'http://aegis.example.com' })[0]).toMatch(/^APP_ORIGIN/);
    expect(issues({ ...prod, DATABASE_URL: 'postgres://a:b@db/aegis?sslmode=disable' })[0]).toMatch(
      /^DATABASE_URL/,
    );
  });
});
