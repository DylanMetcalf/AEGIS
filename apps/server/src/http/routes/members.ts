import {
  addMemberRequestSchema,
  updateMemberRequestSchema,
  uuidSchema,
  type MemberDto,
  type MembershipStatus,
  type PrincipalKind,
  type TenantRole,
} from '@aegis/shared';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { DbClient } from '../../db/pool.js';
import { auditInTx, inTenant, type AppDeps } from '../context.js';
import { Errors, parse } from '../errors.js';

interface MemberRow {
  id: string;
  principal_id: string;
  display_name: string;
  email: string | null;
  kind: PrincipalKind;
  role: TenantRole;
  status: MembershipStatus;
  created_at: Date;
}

const toDto = (r: MemberRow): MemberDto => ({
  id: r.id,
  principalId: r.principal_id,
  displayName: r.display_name,
  email: r.email,
  kind: r.kind,
  role: r.role,
  status: r.status,
  createdAt: r.created_at.toISOString(),
});

const MEMBER_SELECT = `SELECT m.id, m.principal_id, p.display_name, p.email, p.kind, m.role, m.status, m.created_at
  FROM memberships m JOIN principals p ON p.id = m.principal_id`;

const ROLE_FOR_KIND: Record<PrincipalKind, (r: TenantRole) => boolean> = {
  HUMAN: (r) => r !== 'SERVICE' && r !== 'AI_WORKER',
  SERVICE: (r) => r === 'SERVICE',
  AI_WORKER: (r) => r === 'AI_WORKER',
};

/** Lock and count active tenant admins, so concurrent demotions cannot remove the last one. */
async function activeAdminIds(client: DbClient, tenantId: string): Promise<string[]> {
  const { rows } = await client.query<{ id: string }>(
    `SELECT id FROM memberships WHERE tenant_id = $1 AND role = 'TENANT_ADMIN' AND status = 'ACTIVE' FOR UPDATE`,
    [tenantId],
  );
  return rows.map((r) => r.id);
}

export const memberRoutes = (deps: AppDeps) => async (app: FastifyInstance) => {
  app.get('/api/members', { config: { auth: 'membership.read' } }, async (req) => {
    const items = await inTenant(deps, req, async (c, tenantId) => {
      // Membership lists are small; bounded rather than paginated.
      const { rows } = await c.query<MemberRow>(
        `${MEMBER_SELECT} WHERE m.tenant_id = $1 ORDER BY m.created_at LIMIT 500`,
        [tenantId],
      );
      return rows.map(toDto);
    });
    return { items };
  });

  app.post('/api/members', { config: { auth: 'membership.manage' } }, async (req, reply) => {
    const body = parse(addMemberRequestSchema, req.body);
    const member = await inTenant(deps, req, async (c, tenantId) => {
      const { rows: principals } = await c.query<{ id: string; kind: PrincipalKind; status: string }>(
        'SELECT id, kind, status FROM principals WHERE email = $1',
        [body.email],
      );
      const principal = principals[0];
      if (!principal || principal.status !== 'ACTIVE') {
        throw Errors.unprocessable('PRINCIPAL_NOT_ELIGIBLE', 'No active account with that email can be added');
      }
      if (!ROLE_FOR_KIND[principal.kind](body.role)) {
        throw Errors.validation([{ path: 'role', message: `Role not permitted for ${principal.kind} identities` }]);
      }
      const { rows } = await c.query<{ id: string }>(
        `INSERT INTO memberships (tenant_id, principal_id, role, created_by)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (tenant_id, principal_id) DO UPDATE
           SET role = EXCLUDED.role, status = 'ACTIVE'
           WHERE memberships.status = 'REMOVED'
         RETURNING id`,
        [tenantId, principal.id, body.role, req.actor!.principalId],
      );
      if (!rows[0]) throw Errors.conflict('That account is already a member of this tenant');
      await auditInTx(c, req, {
        tenantId,
        action: 'membership.create',
        outcome: 'SUCCESS',
        targetType: 'membership',
        targetId: rows[0].id,
        metadata: { principalId: principal.id, role: body.role },
      });
      const { rows: out } = await c.query<MemberRow>(`${MEMBER_SELECT} WHERE m.id = $1`, [rows[0].id]);
      return toDto(out[0]!);
    });
    return reply.status(201).send(member);
  });

  app.patch('/api/members/:id', { config: { auth: 'membership.manage' } }, async (req) => {
    const { id } = parse(z.object({ id: uuidSchema }).strict(), req.params);
    const body = parse(updateMemberRequestSchema, req.body);
    return inTenant(deps, req, async (c, tenantId) => {
      const admins = await activeAdminIds(c, tenantId);
      const { rows } = await c.query<MemberRow>(`${MEMBER_SELECT} WHERE m.tenant_id = $1 AND m.id = $2 FOR UPDATE OF m`, [
        tenantId,
        id,
      ]);
      const existing = rows[0];
      if (!existing) throw Errors.notFound('Member');
      const nextRole = body.role ?? existing.role;
      const nextStatus = body.status ?? existing.status;
      if (!ROLE_FOR_KIND[existing.kind](nextRole)) {
        throw Errors.validation([{ path: 'role', message: `Role not permitted for ${existing.kind} identities` }]);
      }
      const losesAdmin =
        existing.role === 'TENANT_ADMIN' &&
        existing.status === 'ACTIVE' &&
        (nextRole !== 'TENANT_ADMIN' || nextStatus !== 'ACTIVE');
      if (losesAdmin && admins.length <= 1) {
        throw Errors.unprocessable('LAST_TENANT_ADMIN', 'A tenant must keep at least one active tenant administrator');
      }
      await c.query('UPDATE memberships SET role = $3, status = $4 WHERE tenant_id = $1 AND id = $2', [
        tenantId,
        id,
        nextRole,
        nextStatus,
      ]);
      await auditInTx(c, req, {
        tenantId,
        action: 'membership.update',
        outcome: 'SUCCESS',
        targetType: 'membership',
        targetId: id,
        metadata: {
          principalId: existing.principal_id,
          from: { role: existing.role, status: existing.status },
          to: { role: nextRole, status: nextStatus },
        },
      });
      return toDto({ ...existing, role: nextRole, status: nextStatus });
    });
  });
};
