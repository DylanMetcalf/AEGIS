import { selectTenantRequestSchema, uuidSchema, type SessionInfo, type SessionSummary, type TenantRole } from '@aegis/shared';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { recordAudit, recordAuditIndependently } from '../../audit/audit.js';
import { effectiveCapabilities } from '../../authz/authorize.js';
import { withTransaction } from '../../db/pool.js';
import { listActiveSessions, revokeSession } from '../../identity/sessions.js';
import { auditBase, requireActor, type AppDeps } from '../context.js';
import { Errors, parse } from '../errors.js';

export const sessionRoutes = (deps: AppDeps) => async (app: FastifyInstance) => {
  const { pool, config } = deps;

  app.get('/api/session', { config: { auth: 'session' } }, async (req): Promise<SessionInfo> => {
    const actor = requireActor(req);
    const session = req.session!;
    const memberships = await withTransaction(pool, { tenantId: null, principalId: actor.principalId }, (c) =>
      c.query<{ tenant_id: string; slug: string; display_name: string; role: TenantRole }>(
        `SELECT m.tenant_id, t.slug, t.display_name, m.role
           FROM memberships m JOIN tenants t ON t.id = m.tenant_id
          WHERE m.principal_id = $1 AND m.status = 'ACTIVE' AND t.status = 'ACTIVE'
          ORDER BY t.display_name`,
        [actor.principalId],
      ),
    );
    const reauthUntil = actor.reauthenticatedAt
      ? new Date(actor.reauthenticatedAt.getTime() + config.session.reauthWindowMs)
      : null;
    return {
      principal: {
        id: actor.principalId,
        kind: actor.kind,
        displayName: session.principal.displayName,
        email: session.principal.email,
        platformRole: actor.platformRole,
      },
      activeTenant:
        req.activeTenant && actor.role && actor.membershipStatus === 'ACTIVE' && actor.tenantStatus === 'ACTIVE'
          ? { ...req.activeTenant, role: actor.role }
          : null,
      memberships: memberships.rows.map((m) => ({
        tenantId: m.tenant_id,
        slug: m.slug,
        displayName: m.display_name,
        role: m.role,
      })),
      capabilities: effectiveCapabilities(actor),
      session: {
        id: session.id,
        expiresAt: session.expiresAt.toISOString(),
        idleExpiresAt: new Date(Date.now() + config.session.idleTtlMs).toISOString(),
        reauthenticatedUntil: reauthUntil && reauthUntil.getTime() > Date.now() ? reauthUntil.toISOString() : null,
      },
    };
  });

  app.put('/api/session/tenant', { config: { auth: 'session' } }, async (req, reply) => {
    const actor = requireActor(req);
    const { tenantId } = parse(selectTenantRequestSchema, req.body);
    // The requested tenant is only a hint: membership is verified server-side.
    const ok = await withTransaction(pool, { tenantId: null, principalId: actor.principalId }, async (c) => {
      const { rowCount } = await c.query(
        `SELECT 1 FROM memberships m JOIN tenants t ON t.id = m.tenant_id
          WHERE m.tenant_id = $1 AND m.principal_id = $2 AND m.status = 'ACTIVE' AND t.status = 'ACTIVE'`,
        [tenantId, actor.principalId],
      );
      return rowCount === 1;
    });
    if (!ok) {
      await recordAuditIndependently(
        pool,
        {
          ...auditBase(req),
          tenantId: null,
          action: 'session.tenant_select',
          outcome: 'DENIED',
          reasonCode: 'NOT_A_MEMBER',
          targetType: 'tenant',
          targetId: tenantId,
        },
        (err) => req.log.error({ err }, 'failed to audit tenant selection'),
      );
      throw Errors.forbidden();
    }
    await withTransaction(pool, { tenantId, principalId: actor.principalId }, async (c) => {
      await c.query('UPDATE sessions SET active_tenant_id = $2 WHERE id = $1', [actor.sessionId, tenantId]);
      await recordAudit(c, {
        ...auditBase(req),
        tenantId,
        action: 'session.tenant_select',
        outcome: 'SUCCESS',
        targetType: 'tenant',
        targetId: tenantId,
      });
    });
    return reply.status(204).send();
  });

  app.get('/api/sessions', { config: { auth: 'session' } }, async (req): Promise<{ items: SessionSummary[] }> => {
    const actor = requireActor(req);
    const rows = await withTransaction(pool, { tenantId: null, principalId: actor.principalId }, (c) =>
      listActiveSessions(c, actor.principalId),
    );
    return {
      items: rows.map((r) => ({
        id: r.id,
        createdAt: r.created_at.toISOString(),
        lastSeenAt: r.last_seen_at.toISOString(),
        expiresAt: r.expires_at.toISOString(),
        userAgent: r.user_agent,
        current: r.id === actor.sessionId,
      })),
    };
  });

  app.delete('/api/sessions/:id', { config: { auth: 'session' } }, async (req, reply) => {
    const actor = requireActor(req);
    const { id } = parse(z.object({ id: uuidSchema }).strict(), req.params);
    const found = await withTransaction(pool, { tenantId: null, principalId: actor.principalId }, async (c) => {
      // Only the caller's own sessions are addressable.
      const { rowCount } = await c.query(
        'SELECT 1 FROM sessions WHERE id = $1 AND principal_id = $2 AND revoked_at IS NULL',
        [id, actor.principalId],
      );
      if (rowCount !== 1) return false;
      await revokeSession(c, id, 'USER_REVOKED');
      await recordAudit(c, {
        ...auditBase(req),
        tenantId: null,
        action: 'session.revoke',
        outcome: 'SUCCESS',
        targetType: 'session',
        targetId: id,
      });
      return true;
    });
    if (!found) throw Errors.notFound('Session');
    return reply.status(204).send();
  });
};
