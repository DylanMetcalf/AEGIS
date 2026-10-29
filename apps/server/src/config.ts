import { z } from 'zod';

/**
 * Validated runtime configuration.
 *
 * Defaults are the secure choice; development conveniences (insecure cookies,
 * private-network probing, the test adapter) must be enabled explicitly and
 * are rejected outright in staging and production. Errors name the offending
 * variable but never echo its value.
 */

const bool = (def: boolean) =>
  z
    .enum(['true', 'false'])
    .default(def ? 'true' : 'false')
    .transform((v) => v === 'true');

const int = (def: number, min: number, max: number) =>
  z.coerce.number().int().min(min).max(max).default(def);

const postgresUrl = z
  .string()
  .url()
  .refine((v) => /^postgres(ql)?:\/\//.test(v), 'Must be a postgres:// URL');

const envSchema = z
  .object({
    AEGIS_ENV: z.enum(['development', 'test', 'staging', 'production']),
    HOST: z.string().default('127.0.0.1'),
    PORT: int(3000, 1, 65535),
    APP_ORIGIN: z
      .string()
      .url()
      .refine((v) => new URL(v).origin === v.replace(/\/$/, ''), 'Must be an origin (scheme://host[:port])'),
    TRUST_PROXY: bool(false),

    DATABASE_URL: postgresUrl,
    DATABASE_POOL_MAX: int(10, 1, 100),
    DATABASE_STATEMENT_TIMEOUT_MS: int(10000, 100, 120000),

    SESSION_COOKIE_SECURE: bool(true),
    SESSION_ABSOLUTE_TTL_MINUTES: int(720, 5, 10080),
    SESSION_IDLE_TTL_MINUTES: int(30, 1, 1440),
    REAUTH_WINDOW_MINUTES: int(10, 1, 60),
    LOGIN_MAX_FAILURES: int(5, 1, 100),
    LOGIN_LOCKOUT_MINUTES: int(15, 1, 1440),
    RATE_LIMIT_PER_MINUTE: int(300, 10, 100000),
    LOGIN_RATE_LIMIT_PER_MINUTE: int(20, 1, 100000),
    BODY_LIMIT_BYTES: int(65536, 1024, 1048576),

    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),

    WORKER_ENABLED: bool(true),
    WORKER_CONCURRENCY: int(2, 1, 16),
    WORKER_POLL_INTERVAL_MS: int(1000, 100, 60000),

    INTEGRATION_ALLOW_PRIVATE_NETWORK: bool(false),
    INTEGRATION_ALLOW_INSECURE_HTTP: bool(false),
    INTEGRATION_TEST_ADAPTER_ENABLED: bool(false),
    HEALTH_STALE_AFTER_MINUTES: int(30, 1, 10080),

    WEB_DIST_DIR: z.string().optional(),
  })
  .superRefine((env, ctx) => {
    const hardened = env.AEGIS_ENV === 'production' || env.AEGIS_ENV === 'staging';
    if (!hardened) return;
    const forbid = (key: keyof typeof env, message: string) =>
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: [key], message });
    if (!env.SESSION_COOKIE_SECURE) forbid('SESSION_COOKIE_SECURE', 'Must be true outside development');
    if (!env.APP_ORIGIN.startsWith('https://')) forbid('APP_ORIGIN', 'Must use https outside development');
    if (env.INTEGRATION_ALLOW_PRIVATE_NETWORK)
      forbid('INTEGRATION_ALLOW_PRIVATE_NETWORK', 'Not permitted outside development');
    if (env.INTEGRATION_ALLOW_INSECURE_HTTP)
      forbid('INTEGRATION_ALLOW_INSECURE_HTTP', 'Not permitted outside development');
    if (env.INTEGRATION_TEST_ADAPTER_ENABLED)
      forbid('INTEGRATION_TEST_ADAPTER_ENABLED', 'Test adapters are not permitted outside development');
    if (env.LOG_LEVEL === 'trace' || env.LOG_LEVEL === 'debug')
      forbid('LOG_LEVEL', 'debug/trace logging is not permitted outside development');
    if (env.AEGIS_ENV === 'production') {
      const sslmode = safeSslMode(env.DATABASE_URL);
      if (!sslmode || !['require', 'verify-ca', 'verify-full'].includes(sslmode))
        forbid('DATABASE_URL', 'Production requires sslmode=require, verify-ca, or verify-full');
    }
  });

function safeSslMode(url: string): string | null {
  try {
    return new URL(url).searchParams.get('sslmode');
  } catch {
    return null;
  }
}

export type AppConfig = ReturnType<typeof toConfig>;

export class ConfigError extends Error {
  constructor(public readonly issues: string[]) {
    super(`Invalid configuration:\n${issues.map((i) => `  - ${i}`).join('\n')}`);
    this.name = 'ConfigError';
  }
}

function toConfig(env: z.infer<typeof envSchema>) {
  return {
    env: env.AEGIS_ENV,
    isProductionLike: env.AEGIS_ENV === 'production' || env.AEGIS_ENV === 'staging',
    host: env.HOST,
    port: env.PORT,
    appOrigin: env.APP_ORIGIN.replace(/\/$/, ''),
    trustProxy: env.TRUST_PROXY,
    database: {
      url: env.DATABASE_URL,
      poolMax: env.DATABASE_POOL_MAX,
      statementTimeoutMs: env.DATABASE_STATEMENT_TIMEOUT_MS,
    },
    session: {
      cookieSecure: env.SESSION_COOKIE_SECURE,
      // __Host- prefix forces Secure, Path=/ and no Domain in the browser.
      cookieName: env.SESSION_COOKIE_SECURE ? '__Host-aegis_session' : 'aegis_session',
      absoluteTtlMs: env.SESSION_ABSOLUTE_TTL_MINUTES * 60_000,
      idleTtlMs: env.SESSION_IDLE_TTL_MINUTES * 60_000,
      reauthWindowMs: env.REAUTH_WINDOW_MINUTES * 60_000,
    },
    auth: {
      maxFailures: env.LOGIN_MAX_FAILURES,
      lockoutMs: env.LOGIN_LOCKOUT_MINUTES * 60_000,
    },
    http: {
      rateLimitPerMinute: env.RATE_LIMIT_PER_MINUTE,
      loginRateLimitPerMinute: env.LOGIN_RATE_LIMIT_PER_MINUTE,
      bodyLimitBytes: env.BODY_LIMIT_BYTES,
    },
    logLevel: env.LOG_LEVEL,
    worker: {
      enabled: env.WORKER_ENABLED,
      concurrency: env.WORKER_CONCURRENCY,
      pollIntervalMs: env.WORKER_POLL_INTERVAL_MS,
    },
    integrations: {
      allowPrivateNetwork: env.INTEGRATION_ALLOW_PRIVATE_NETWORK,
      allowInsecureHttp: env.INTEGRATION_ALLOW_INSECURE_HTTP,
      testAdapterEnabled: env.INTEGRATION_TEST_ADAPTER_ENABLED,
    },
    health: {
      staleAfterMs: env.HEALTH_STALE_AFTER_MINUTES * 60_000,
    },
    webDistDir: env.WEB_DIST_DIR ?? null,
  };
}

/** Error messages that never include the received value. */
const valueFreeErrorMap: z.ZodErrorMap = (issue, ctx) => {
  if (issue.code === z.ZodIssueCode.invalid_enum_value) {
    return { message: `Expected one of: ${issue.options.join(', ')}` };
  }
  if (issue.code === z.ZodIssueCode.invalid_type) {
    return { message: issue.received === 'undefined' ? 'Required' : `Expected ${issue.expected}` };
  }
  return { message: ctx.defaultError };
};

/** Parse configuration from an environment map. Throws ConfigError without leaking values. */
export function loadConfig(source: NodeJS.ProcessEnv = process.env): AppConfig {
  const result = envSchema.safeParse(source, { errorMap: valueFreeErrorMap });
  if (!result.success) {
    throw new ConfigError(
      result.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`),
    );
  }
  return toConfig(result.data);
}
