import { auditListQuerySchema, createTenantRequestSchema } from '@aegis/shared';
import type { FastifyInstance } from 'fastify';
import { listAuditEvents, recordAudit, verifyAuditChain } from '../../audit/audit.js';
import { withTransaction } from '../../db/pool.js';
import type { AuditVerificationState } from '../../health/health.js';
import { auditBase, requireActor, type AppDeps } from '../context.js';
import { parse } from '../errors.js';
import { auditCursor } from './audit.js';

/**
 * Platform administration (SYSTEM_OWNER). Platform scope grants tenant
 * lifecycle and platform-level audit access only; it does not grant access
 * to any tenant's assets, integrations, or tenant audit events.
 */
export const platformRoutes =
  (deps: AppDeps, verification: AuditVerificationState) => async (app: FastifyInstance) => {
    const { pool } = deps;

    app.get('/api/platform/tenants', { config: { auth: 'platform.tenant.read' } }, async (req) => {
      const actor = requireActor(req);
      const { rows } = await withTransaction(
        pool,
        { tenantId: null, principalId: actor.principalId, platformScope: true },
        (c) =>
          c.query<{
            id: string;
            slug: string;
            display_name: string;
            status: string;
            created_at: Date;
          }>(
            'SELECT id, slug, display_name, status, created_at FROM tenants ORDER BY created_at LIMIT 500',
          ),
      );
      return {
        items: rows.map((r) => ({
          id: r.id,
          slug: r.slug,
          displayName: r.display_name,
          status: r.status,
          createdAt: r.created_at.toISOString(),
        })),
      };
    });

    app.post(
      '/api/platform/tenants',
      { config: { auth: 'platform.tenant.manage' } },
      async (req, reply) => {
        const actor = requireActor(req);
        const body = parse(createTenantRequestSchema, req.body);
        const tenant = await withTransaction(
          pool,
          { tenantId: null, principalId: actor.principalId, platformScope: true },
          async (c) => {
            const { rows } = await c.query<{ id: string; slug: string; display_name: string }>(
              `INSERT INTO tenants (slug, display_name, created_by) VALUES ($1, $2, $3)
           RETURNING id, slug, display_name`,
              [body.slug, body.displayName, actor.principalId],
            );
            const t = rows[0]!;
            if (body.addCreatorAsAdmin) {
              await c.query(
                `INSERT INTO memberships (tenant_id, principal_id, role, created_by) VALUES ($1, $2, 'TENANT_ADMIN', $2)`,
                [t.id, actor.principalId],
              );
            }
            await recordAudit(c, {
              ...auditBase(req),
              tenantId: null,
              action: 'tenant.create',
              outcome: 'SUCCESS',
              targetType: 'tenant',
              targetId: t.id,
              metadata: { slug: t.slug, creatorAddedAsAdmin: body.addCreatorAsAdmin },
            });
            return t;
          },
        );
        return reply
          .status(201)
          .send({ id: tenant.id, slug: tenant.slug, displayName: tenant.display_name });
      },
    );

    app.get(
      '/api/platform/audit-events',
      { config: { auth: 'platform.audit.read' } },
      async (req) => {
        const actor = requireActor(req);
        const q = parse(auditListQuerySchema, req.query);
        const beforePosition = auditCursor(q.cursor);
        return withTransaction(
          pool,
          { tenantId: null, principalId: actor.principalId, platformScope: true },
          (c) =>
            listAuditEvents(c, {
              scope: 'platform',
              limit: q.limit,
              beforePosition,
              action: q.action,
              outcome: q.outcome,
            }),
        );
      },
    );

    app.post(
      '/api/platform/audit/verify',
      { config: { auth: 'platform.audit.verify' } },
      async (req) => {
        const actor = requireActor(req);
        const result = await verifyAuditChain(pool);
        verification.set(result);
        await withTransaction(pool, { tenantId: null, principalId: actor.principalId }, (c) =>
          recordAudit(c, {
            ...auditBase(req),
            tenantId: null,
            action: 'audit.chain_verify',
            outcome: result.verified ? 'SUCCESS' : 'FAILURE',
            reasonCode: result.reason,
            metadata: {
              eventsChecked: result.eventsChecked,
              headPosition: result.headPosition,
              headHash: result.headHash,
            },
          }),
        );
        return result;
      },
    );
  };
