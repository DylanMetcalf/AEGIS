import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { Writable } from 'node:stream';
import cookie from '@fastify/cookie';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import fastifyStatic from '@fastify/static';
import Fastify, { type FastifyError, type FastifyInstance, type FastifyRequest } from 'fastify';
import type { Actor } from '../authz/authorize.js';
import { isCapability } from '../authz/capabilities.js';
import type { AppConfig } from '../config.js';
import { withTransaction, type Pool } from '../db/pool.js';
import { AuditVerificationState } from '../health/health.js';
import {
  evaluateSession,
  findSessionByToken,
  revokeSession,
  touchSession,
} from '../identity/sessions.js';
import type { ProviderRegistry } from '../integrations/registry.js';
import { LOG_REDACT_PATHS } from '../security/redact.js';
import { enforce, type AppDeps } from './context.js';
import { AppError, Errors } from './errors.js';
import { assetRoutes } from './routes/assets.js';
import { auditRoutes } from './routes/audit.js';
import { authRoutes } from './routes/auth.js';
import { healthRoutes } from './routes/health.js';
import { integrationRoutes } from './routes/integrations.js';
import { memberRoutes } from './routes/members.js';
import { overviewRoutes } from './routes/overview.js';
import { platformRoutes } from './routes/platform.js';
import { sessionRoutes } from './routes/session.js';

export interface BuildAppOptions {
  config: AppConfig;
  pool: Pool;
  providers: ProviderRegistry;
  /** Optional log destination (tests capture logs to check redaction). */
  logStream?: Writable;
}

export interface App extends FastifyInstance {
  deps: AppDeps;
  auditVerification: AuditVerificationState;
}

const CORRELATION_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export async function buildApp(opts: BuildAppOptions): Promise<App> {
  const { config, pool, providers } = opts;
  const app = Fastify({
    logger: {
      level: config.logLevel,
      redact: { paths: LOG_REDACT_PATHS, censor: '[REDACTED]' },
      ...(opts.logStream ? { stream: opts.logStream } : {}),
    },
    genReqId: () => randomUUID(),
    requestIdHeader: false,
    requestIdLogLabel: 'requestId',
    bodyLimit: config.http.bodyLimitBytes,
    trustProxy: config.trustProxy,
    disableRequestLogging: false,
    return503OnClosing: true,
    routerOptions: { maxParamLength: 200 },
  }) as unknown as App;

  const deps: AppDeps = { config, pool, providers };
  app.decorate('deps', deps);
  app.decorate('auditVerification', new AuditVerificationState());
  app.decorateRequest('actor', null);
  app.decorateRequest('session', null);
  app.decorateRequest('activeTenant', null);
  app.decorateRequest('correlationId', '');

  // Only JSON request bodies are accepted. Removing the text/plain parser
  // means cross-site "simple" form posts cannot reach handlers.
  app.removeContentTypeParser('text/plain');

  // Every /api route must declare its protection, or startup fails.
  app.addHook('onRoute', (route) => {
    if (!route.url.startsWith('/api')) return;
    const auth = route.config?.auth;
    if (auth === undefined) {
      throw new Error(`Route ${route.method} ${route.url} does not declare config.auth`);
    }
    if (auth !== 'public' && auth !== 'session' && !isCapability(auth)) {
      throw new Error(`Route ${route.method} ${route.url} declares unknown capability ${auth}`);
    }
  });

  await app.register(helmet, {
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        fontSrc: ["'self'"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        ...(config.session.cookieSecure ? { upgradeInsecureRequests: [] } : {}),
      },
    },
    hsts: config.session.cookieSecure ? { maxAge: 31536000, includeSubDomains: true } : false,
    referrerPolicy: { policy: 'no-referrer' },
    crossOriginEmbedderPolicy: false,
  });
  await app.register(cookie);
  await app.register(rateLimit, {
    global: true,
    max: config.http.rateLimitPerMinute,
    timeWindow: 60_000,
    errorResponseBuilder: () => {
      const err = Errors.rateLimited();
      return { statusCode: err.statusCode, code: err.code, message: err.message };
    },
  });

  app.addHook('onRequest', async (req, reply) => {
    const incoming = req.headers['x-correlation-id'];
    req.correlationId =
      typeof incoming === 'string' && CORRELATION_RE.test(incoming) ? incoming : req.id;
    reply.header('x-request-id', req.id);
    reply.header('x-correlation-id', req.correlationId);
    if (req.url.startsWith('/api')) reply.header('cache-control', 'no-store');

    // CSRF / origin enforcement for state-changing API requests. Combined
    // with SameSite=Strict cookies and JSON-only bodies.
    if (req.url.startsWith('/api') && UNSAFE_METHODS.has(req.method)) {
      const origin = req.headers.origin;
      if (origin !== config.appOrigin) throw Errors.csrf();
    }
  });

  app.addHook('preHandler', async (req) => {
    if (!req.url.startsWith('/api')) return;
    await resolveSession(app, req);
    const auth = req.routeOptions.config.auth;
    if (auth === 'public' || auth === undefined) return;
    if (!req.actor) throw Errors.unauthenticated();
    if (auth !== 'session') await enforce(deps, req, auth);
  });

  app.setErrorHandler((err: FastifyError | AppError | Error, req, reply) => {
    const safe = toSafeError(err);
    if (safe.statusCode >= 500) req.log.error({ err }, 'request failed');
    else req.log.info({ code: safe.code, statusCode: safe.statusCode }, 'request rejected');
    void reply.status(safe.statusCode).send({
      error: {
        code: safe.code,
        message: safe.message,
        requestId: req.id,
        ...(safe.details ? { details: safe.details } : {}),
      },
    });
  });

  await app.register(healthRoutes(deps, app.auditVerification));
  await app.register(authRoutes(deps));
  await app.register(sessionRoutes(deps));
  await app.register(memberRoutes(deps));
  await app.register(assetRoutes(deps));
  await app.register(integrationRoutes(deps));
  await app.register(auditRoutes(deps));
  await app.register(platformRoutes(deps, app.auditVerification));
  await app.register(overviewRoutes(deps, app.auditVerification));

  const webDist = config.webDistDir;
  if (webDist && existsSync(join(webDist, 'index.html'))) {
    await app.register(fastifyStatic, { root: webDist, index: ['index.html'], wildcard: false });
  }

  app.setNotFoundHandler((req, reply) => {
    // SPA fallback for client-side routes only. A missing asset (anything with
    // a file extension) is a real 404, never index.html served as script/CSS.
    const pathname = req.url.split('?')[0] ?? '';
    const isNavigation = !/\.[A-Za-z0-9]+$/.test(pathname) && !pathname.startsWith('/health');
    if (
      !req.url.startsWith('/api') &&
      isNavigation &&
      webDist &&
      req.method === 'GET' &&
      existsSync(join(webDist, 'index.html'))
    ) {
      return reply.type('text/html').sendFile('index.html');
    }
    const err = Errors.notFound('Route');
    return reply
      .status(404)
      .send({ error: { code: err.code, message: err.message, requestId: req.id } });
  });

  return app;
}

/**
 * Resolve the session cookie into an actor. Invalid, expired, or revoked
 * sessions result in no actor (and a cleared cookie), never an error that
 * reveals why.
 */
async function resolveSession(app: App, req: FastifyRequest): Promise<void> {
  const { config, pool } = app.deps;
  const token = req.cookies[config.session.cookieName];
  if (!token) return;
  const session = await findSessionByToken(pool, token);
  if (!session) return;
  const validity = evaluateSession(session, config.session.idleTtlMs);
  if (validity !== 'VALID') {
    if (validity === 'IDLE_EXPIRED' || validity === 'PRINCIPAL_INACTIVE') {
      await revokeSession(
        pool,
        session.id,
        validity === 'PRINCIPAL_INACTIVE' ? 'PRINCIPAL_DISABLED' : 'LOGOUT',
      );
    }
    return;
  }

  let tenant:
    | {
        id: string;
        slug: string;
        display_name: string;
        status: 'ACTIVE' | 'SUSPENDED';
        role: Actor['role'];
        membership_status: Actor['membershipStatus'];
      }
    | undefined;
  if (session.activeTenantId) {
    tenant = await withTransaction(
      pool,
      { tenantId: null, principalId: session.principalId },
      async (client) =>
        (
          await client.query(
            `SELECT t.id, t.slug, t.display_name, t.status, m.role, m.status AS membership_status
               FROM tenants t JOIN memberships m ON m.tenant_id = t.id AND m.principal_id = $2
              WHERE t.id = $1`,
            [session.activeTenantId, session.principalId],
          )
        ).rows[0],
    );
  }

  req.session = session;
  req.activeTenant = tenant
    ? { id: tenant.id, slug: tenant.slug, displayName: tenant.display_name }
    : null;
  req.actor = {
    principalId: session.principalId,
    kind: session.principal.kind,
    status: session.principal.status,
    platformRole: session.principal.platformRole,
    tenantId: tenant?.id ?? null,
    tenantStatus: tenant?.status ?? null,
    role: tenant?.role ?? null,
    membershipStatus: tenant?.membership_status ?? null,
    sessionId: session.id,
    reauthenticatedAt: session.reauthenticatedAt,
  };
  await touchSession(pool, session.id);
}

function toSafeError(err: FastifyError | AppError | Error): AppError {
  if (err instanceof AppError) return err;
  const fe = err as FastifyError & { code?: string; statusCode?: number };
  switch (fe.code) {
    case 'FST_ERR_CTP_BODY_TOO_LARGE':
      return new AppError(413, 'PAYLOAD_TOO_LARGE', 'Request body is too large');
    case 'FST_ERR_CTP_INVALID_MEDIA_TYPE':
    case 'FST_ERR_CTP_INVALID_CONTENT_LENGTH':
      return Errors.unsupportedMediaType();
    case 'FST_ERR_CTP_EMPTY_JSON_BODY':
    case 'FST_ERR_CTP_INVALID_JSON_BODY':
      return Errors.validation(undefined, 'Malformed JSON body');
    case 'FST_ERR_VALIDATION':
      return Errors.validation();
    case '23505': // unique_violation
      return Errors.conflict('A resource with these details already exists');
    case '23503': // foreign_key_violation
      return Errors.validation(undefined, 'Referenced resource does not exist');
    case '23514': // check_violation
    case '22P02': // invalid_text_representation
    case '22001': // string_data_right_truncation
    case '22003': // numeric_value_out_of_range
    case '22007': // invalid_datetime_format
    case '22008': // datetime_field_overflow
      return Errors.validation();
    case '42501': // insufficient_privilege, including RLS violations
      return Errors.forbidden();
  }
  if (fe.statusCode === 429) return Errors.rateLimited();
  if (err instanceof SyntaxError) return Errors.validation(undefined, 'Malformed JSON body');
  if (fe.statusCode && fe.statusCode >= 400 && fe.statusCode < 500) {
    return new AppError(fe.statusCode, 'BAD_REQUEST', 'The request could not be processed');
  }
  return Errors.internal();
}
