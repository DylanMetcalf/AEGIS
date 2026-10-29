import { withTransaction, type Pool } from '../db/pool.js';
import type { Actor } from './authorize.js';

/**
 * Build an Actor for a principal acting in a tenant without an interactive
 * session (background jobs, ingest service identities). State is read fresh
 * from the database, so revoked memberships take effect immediately.
 */
export async function loadActorForTenant(
  pool: Pool,
  tenantId: string,
  principalId: string,
): Promise<Actor | null> {
  return withTransaction(pool, { tenantId, principalId }, async (client) => {
    const { rows } = await client.query<{
      kind: Actor['kind'];
      status: Actor['status'];
      platform_role: Actor['platformRole'];
      tenant_status: 'ACTIVE' | 'SUSPENDED';
      role: Actor['role'];
      membership_status: Actor['membershipStatus'];
    }>(
      `SELECT p.kind, p.status, p.platform_role, t.status AS tenant_status,
              m.role, m.status AS membership_status
         FROM principals p
         JOIN tenants t ON t.id = $1
         LEFT JOIN memberships m ON m.tenant_id = t.id AND m.principal_id = p.id
        WHERE p.id = $2`,
      [tenantId, principalId],
    );
    const r = rows[0];
    if (!r) return null;
    return {
      principalId,
      kind: r.kind,
      status: r.status,
      platformRole: r.platform_role,
      tenantId,
      tenantStatus: r.tenant_status,
      role: r.role,
      membershipStatus: r.membership_status,
      sessionId: null,
      reauthenticatedAt: null,
    };
  });
}
