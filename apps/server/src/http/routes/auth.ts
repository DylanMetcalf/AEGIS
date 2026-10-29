import {
  changePasswordRequestSchema,
  loginRequestSchema,
  reauthenticateRequestSchema,
} from '@aegis/shared';
import type { FastifyInstance, FastifyReply } from 'fastify';
import { recordAudit, recordAuditIndependently } from '../../audit/audit.js';
import type { AppConfig } from '../../config.js';
import { NO_CONTEXT, withTransaction } from '../../db/pool.js';
import {
  createSession,
  revokeSession,
  revokeSessionsForPrincipal,
} from '../../identity/sessions.js';
import {
  accountKey,
  clearFailures,
  clientKey,
  isLocked,
  registerFailure,
} from '../../identity/throttle.js';
import { hashPassword, verifyPassword } from '../../security/passwords.js';
import { auditBase, requireActor, type AppDeps } from '../context.js';
import { Errors, parse } from '../errors.js';

export function setSessionCookie(reply: FastifyReply, config: AppConfig, token: string) {
  void reply.setCookie(config.session.cookieName, token, {
    httpOnly: true,
    secure: config.session.cookieSecure,
    sameSite: 'strict',
    path: '/',
    maxAge: Math.floor(config.session.absoluteTtlMs / 1000),
  });
}

export function clearSessionCookie(reply: FastifyReply, config: AppConfig) {
  void reply.clearCookie(config.session.cookieName, {
    httpOnly: true,
    secure: config.session.cookieSecure,
    sameSite: 'strict',
    path: '/',
  });
}

export const authRoutes = (deps: AppDeps) => async (app: FastifyInstance) => {
  const { pool, config } = deps;
  /** Per-client limit on credential-checking endpoints, in addition to per-account lockout. */
  const LOGIN_RATE_LIMIT = { max: config.http.loginRateLimitPerMinute, timeWindow: 60_000 };

  /** Verify a password for an already-authenticated principal, with throttling. */
  async function verifyOwnPassword(principalId: string, email: string, password: string) {
    const key = accountKey(email);
    if (await withTransaction(pool, NO_CONTEXT, (c) => isLocked(c, [key]))) throw Errors.rateLimited();
    const { rows } = await pool.query<{ password_hash: string | null }>(
      'SELECT password_hash FROM principals WHERE id = $1',
      [principalId],
    );
    const ok = await verifyPassword(rows[0]?.password_hash ?? null, password);
    if (!ok) {
      await withTransaction(pool, NO_CONTEXT, (c) =>
        registerFailure(c, key, config.auth.maxFailures, config.auth.lockoutMs),
      );
    }
    return ok;
  }

  app.post(
    '/api/auth/login',
    { config: { auth: 'public', rateLimit: LOGIN_RATE_LIMIT } },
    async (req, reply) => {
      const body = parse(loginRequestSchema, req.body);
      const keys = { account: accountKey(body.email), client: clientKey(req.ip) };
      const base = { ...auditBase(req), tenantId: null, action: 'auth.login' };
      const logAuditError = (err: unknown) => req.log.error({ err }, 'failed to audit login');

      if (await withTransaction(pool, NO_CONTEXT, (c) => isLocked(c, [keys.account, keys.client]))) {
        await recordAuditIndependently(pool, { ...base, outcome: 'DENIED', reasonCode: 'THROTTLED' }, logAuditError);
        throw Errors.rateLimited();
      }

      const { rows } = await pool.query<{
        id: string;
        kind: string;
        status: string;
        password_hash: string | null;
      }>('SELECT id, kind, status, password_hash FROM principals WHERE email = $1', [body.email]);
      const principal = rows[0];
      // Always run a hash verification, whether or not the account exists.
      const passwordOk = await verifyPassword(
        principal?.kind === 'HUMAN' ? principal.password_hash : null,
        body.password,
      );
      if (!principal || !passwordOk || principal.status !== 'ACTIVE') {
        await withTransaction(pool, NO_CONTEXT, async (c) => {
          await registerFailure(c, keys.account, config.auth.maxFailures, config.auth.lockoutMs);
          await registerFailure(c, keys.client, config.auth.maxFailures * 4, config.auth.lockoutMs);
        });
        await recordAuditIndependently(
          pool,
          {
            ...base,
            outcome: 'DENIED',
            reasonCode: 'INVALID_CREDENTIALS',
            targetType: principal ? 'principal' : null,
            targetId: principal?.id ?? null,
          },
          logAuditError,
        );
        throw Errors.invalidCredentials();
      }

      const previousToken = req.cookies[config.session.cookieName];
      const created = await withTransaction(
        pool,
        { tenantId: null, principalId: principal.id },
        async (client) => {
          await clearFailures(client, keys.account);
          // Never reuse a pre-existing session (fixation): supersede it.
          if (req.session) await revokeSession(client, req.session.id, 'SUPERSEDED');
          const memberships = await client.query<{ tenant_id: string }>(
            `SELECT m.tenant_id FROM memberships m JOIN tenants t ON t.id = m.tenant_id
              WHERE m.principal_id = $1 AND m.status = 'ACTIVE' AND t.status = 'ACTIVE'`,
            [principal.id],
          );
          const activeTenantId = memberships.rows.length === 1 ? memberships.rows[0]!.tenant_id : null;
          const session = await createSession(client, {
            principalId: principal.id,
            activeTenantId,
            userAgent: req.headers['user-agent'] ?? null,
            absoluteTtlMs: config.session.absoluteTtlMs,
          });
          await recordAudit(client, {
            ...base,
            actorPrincipalId: principal.id,
            actorType: 'HUMAN',
            outcome: 'SUCCESS',
            targetType: 'session',
            targetId: session.sessionId,
            metadata: { replacedExistingSession: Boolean(previousToken && req.session) },
          });
          return session;
        },
      );
      setSessionCookie(reply, config, created.token);
      return reply.status(200).send({ authenticated: true, expiresAt: created.expiresAt.toISOString() });
    },
  );

  app.post('/api/auth/logout', { config: { auth: 'public' } }, async (req, reply) => {
    if (req.session && req.actor) {
      const actor = req.actor;
      const sessionId = req.session.id;
      await withTransaction(pool, { tenantId: null, principalId: actor.principalId }, async (c) => {
        await revokeSession(c, sessionId, 'LOGOUT');
        await recordAudit(c, {
          ...auditBase(req),
          tenantId: null,
          action: 'auth.logout',
          outcome: 'SUCCESS',
          targetType: 'session',
          targetId: sessionId,
        });
      });
    }
    clearSessionCookie(reply, config);
    return reply.status(204).send();
  });

  app.post('/api/auth/logout-all', { config: { auth: 'session' } }, async (req, reply) => {
    const actor = requireActor(req);
    const count = await withTransaction(pool, { tenantId: null, principalId: actor.principalId }, async (c) => {
      const n = await revokeSessionsForPrincipal(c, actor.principalId, 'LOGOUT_ALL');
      await recordAudit(c, {
        ...auditBase(req),
        tenantId: null,
        action: 'auth.logout_all',
        outcome: 'SUCCESS',
        targetType: 'principal',
        targetId: actor.principalId,
        metadata: { sessionsRevoked: n },
      });
      return n;
    });
    clearSessionCookie(reply, config);
    return reply.status(200).send({ sessionsRevoked: count });
  });

  app.post(
    '/api/auth/reauthenticate',
    { config: { auth: 'session', rateLimit: LOGIN_RATE_LIMIT } },
    async (req, reply) => {
      const actor = requireActor(req);
      const body = parse(reauthenticateRequestSchema, req.body);
      const email = req.session!.principal.email;
      if (actor.kind !== 'HUMAN' || !email) throw Errors.forbidden();
      const ok = await verifyOwnPassword(actor.principalId, email, body.password);
      if (!ok) {
        await recordAuditIndependently(
          pool,
          { ...auditBase(req), tenantId: null, action: 'auth.reauthenticate', outcome: 'DENIED', reasonCode: 'INVALID_CREDENTIALS' },
          (err) => req.log.error({ err }, 'failed to audit reauthentication'),
        );
        throw Errors.invalidCredentials();
      }
      const until = await withTransaction(pool, { tenantId: null, principalId: actor.principalId }, async (c) => {
        const { rows } = await c.query<{ reauthenticated_at: Date }>(
          'UPDATE sessions SET reauthenticated_at = now() WHERE id = $1 RETURNING reauthenticated_at',
          [actor.sessionId],
        );
        await recordAudit(c, {
          ...auditBase(req),
          tenantId: null,
          action: 'auth.reauthenticate',
          outcome: 'SUCCESS',
          targetType: 'session',
          targetId: actor.sessionId,
        });
        return new Date(rows[0]!.reauthenticated_at.getTime() + config.session.reauthWindowMs);
      });
      return reply.send({ reauthenticatedUntil: until.toISOString() });
    },
  );

  app.post(
    '/api/auth/password',
    { config: { auth: 'session', rateLimit: LOGIN_RATE_LIMIT } },
    async (req, reply) => {
      const actor = requireActor(req);
      const body = parse(changePasswordRequestSchema, req.body);
      const email = req.session!.principal.email;
      if (actor.kind !== 'HUMAN' || !email) throw Errors.forbidden();
      if (!(await verifyOwnPassword(actor.principalId, email, body.currentPassword))) {
        await recordAuditIndependently(
          pool,
          { ...auditBase(req), tenantId: null, action: 'auth.password_change', outcome: 'DENIED', reasonCode: 'INVALID_CREDENTIALS' },
          (err) => req.log.error({ err }, 'failed to audit password change'),
        );
        throw Errors.invalidCredentials();
      }
      const newHash = await hashPassword(body.newPassword);
      const revoked = await withTransaction(pool, { tenantId: null, principalId: actor.principalId }, async (c) => {
        await c.query(
          'UPDATE principals SET password_hash = $2, password_changed_at = now() WHERE id = $1',
          [actor.principalId, newHash],
        );
        const n = await revokeSessionsForPrincipal(c, actor.principalId, 'PASSWORD_CHANGED', actor.sessionId);
        await c.query('UPDATE sessions SET reauthenticated_at = now() WHERE id = $1', [actor.sessionId]);
        await recordAudit(c, {
          ...auditBase(req),
          tenantId: null,
          action: 'auth.password_change',
          outcome: 'SUCCESS',
          targetType: 'principal',
          targetId: actor.principalId,
          metadata: { otherSessionsRevoked: n },
        });
        return n;
      });
      return reply.send({ otherSessionsRevoked: revoked });
    },
  );
};
