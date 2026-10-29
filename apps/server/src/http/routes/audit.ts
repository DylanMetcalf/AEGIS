import { auditListQuerySchema } from '@aegis/shared';
import type { FastifyInstance } from 'fastify';
import { listAuditEvents } from '../../audit/audit.js';
import { inTenant, type AppDeps } from '../context.js';
import { Errors, parse } from '../errors.js';

/** Audit cursors are chain positions (positive integers). */
export function auditCursor(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined;
  if (!/^[1-9][0-9]{0,18}$/.test(raw)) throw Errors.validation([{ path: 'cursor', message: 'Invalid cursor' }]);
  return raw;
}

export const auditRoutes = (deps: AppDeps) => async (app: FastifyInstance) => {
  app.get('/api/audit-events', { config: { auth: 'audit.read' } }, async (req) => {
    const q = parse(auditListQuerySchema, req.query);
    const beforePosition = auditCursor(q.cursor);
    return inTenant(deps, req, (c, tenantId) =>
      listAuditEvents(c, {
        scope: { tenantId },
        limit: q.limit,
        beforePosition,
        action: q.action,
        outcome: q.outcome,
      }),
    );
  });
};
