import type { PlatformRole, PrincipalKind, PrincipalStatus } from '@aegis/shared';
import type { DbClient, Pool } from '../db/pool.js';
import { generateToken, isWellFormedToken, sha256 } from '../security/tokens.js';

/**
 * Server-side sessions. The browser holds an opaque 256-bit token in an
 * HttpOnly cookie; the database stores only its SHA-256, so a database read
 * does not yield usable session tokens.
 */

export type RevokeReason =
  | 'LOGOUT'
  | 'LOGOUT_ALL'
  | 'PASSWORD_CHANGED'
  | 'ADMIN'
  | 'SUPERSEDED'
  | 'PRINCIPAL_DISABLED'
  | 'USER_REVOKED';

export interface SessionWithPrincipal {
  id: string;
  principalId: string;
  activeTenantId: string | null;
  createdAt: Date;
  lastSeenAt: Date;
  expiresAt: Date;
  reauthenticatedAt: Date | null;
  revokedAt: Date | null;
  principal: {
    kind: PrincipalKind;
    status: PrincipalStatus;
    platformRole: PlatformRole | null;
    displayName: string;
    email: string | null;
  };
}

export async function createSession(
  client: DbClient,
  opts: {
    principalId: string;
    activeTenantId: string | null;
    userAgent: string | null;
    absoluteTtlMs: number;
  },
): Promise<{ token: string; sessionId: string; expiresAt: Date }> {
  const token = generateToken();
  const { rows } = await client.query<{ id: string; expires_at: Date }>(
    `INSERT INTO sessions (token_hash, principal_id, active_tenant_id, expires_at, reauthenticated_at, user_agent)
     VALUES ($1, $2, $3, now() + make_interval(secs => $4::double precision / 1000), now(), $5)
     RETURNING id, expires_at`,
    [
      sha256(token),
      opts.principalId,
      opts.activeTenantId,
      opts.absoluteTtlMs,
      opts.userAgent ? opts.userAgent.slice(0, 256) : null,
    ],
  );
  return { token, sessionId: rows[0]!.id, expiresAt: rows[0]!.expires_at };
}

/** Look up a session by its token. Returns null for unknown or malformed tokens. */
export async function findSessionByToken(
  pool: Pool,
  token: string,
): Promise<SessionWithPrincipal | null> {
  if (!isWellFormedToken(token)) return null;
  const { rows } = await pool.query<{
    id: string;
    principal_id: string;
    active_tenant_id: string | null;
    created_at: Date;
    last_seen_at: Date;
    expires_at: Date;
    reauthenticated_at: Date | null;
    revoked_at: Date | null;
    kind: PrincipalKind;
    status: PrincipalStatus;
    platform_role: PlatformRole | null;
    display_name: string;
    email: string | null;
  }>(
    `SELECT s.id, s.principal_id, s.active_tenant_id, s.created_at, s.last_seen_at, s.expires_at,
            s.reauthenticated_at, s.revoked_at,
            p.kind, p.status, p.platform_role, p.display_name, p.email
       FROM sessions s JOIN principals p ON p.id = s.principal_id
      WHERE s.token_hash = $1`,
    [sha256(token)],
  );
  const r = rows[0];
  if (!r) return null;
  return {
    id: r.id,
    principalId: r.principal_id,
    activeTenantId: r.active_tenant_id,
    createdAt: r.created_at,
    lastSeenAt: r.last_seen_at,
    expiresAt: r.expires_at,
    reauthenticatedAt: r.reauthenticated_at,
    revokedAt: r.revoked_at,
    principal: {
      kind: r.kind,
      status: r.status,
      platformRole: r.platform_role,
      displayName: r.display_name,
      email: r.email,
    },
  };
}

export type SessionValidity =
  'VALID' | 'REVOKED' | 'EXPIRED' | 'IDLE_EXPIRED' | 'PRINCIPAL_INACTIVE';

export function evaluateSession(
  s: SessionWithPrincipal,
  idleTtlMs: number,
  now = new Date(),
): SessionValidity {
  if (s.revokedAt) return 'REVOKED';
  if (s.expiresAt.getTime() <= now.getTime()) return 'EXPIRED';
  if (s.lastSeenAt.getTime() + idleTtlMs <= now.getTime()) return 'IDLE_EXPIRED';
  if (s.principal.status !== 'ACTIVE') return 'PRINCIPAL_INACTIVE';
  return 'VALID';
}

export async function touchSession(pool: Pool, sessionId: string): Promise<void> {
  await pool.query(
    `UPDATE sessions SET last_seen_at = now()
      WHERE id = $1 AND revoked_at IS NULL AND last_seen_at < now() - interval '30 seconds'`,
    [sessionId],
  );
}

export async function revokeSession(
  client: DbClient | Pool,
  sessionId: string,
  reason: RevokeReason,
): Promise<void> {
  await client.query(
    `UPDATE sessions SET revoked_at = now(), revoke_reason = $2 WHERE id = $1 AND revoked_at IS NULL`,
    [sessionId, reason],
  );
}

export async function revokeSessionsForPrincipal(
  client: DbClient,
  principalId: string,
  reason: RevokeReason,
  exceptSessionId: string | null = null,
): Promise<number> {
  const res = await client.query(
    `UPDATE sessions SET revoked_at = now(), revoke_reason = $2
      WHERE principal_id = $1 AND revoked_at IS NULL AND ($3::uuid IS NULL OR id <> $3::uuid)`,
    [principalId, reason, exceptSessionId],
  );
  return res.rowCount ?? 0;
}

export async function listActiveSessions(client: DbClient, principalId: string) {
  const { rows } = await client.query<{
    id: string;
    created_at: Date;
    last_seen_at: Date;
    expires_at: Date;
    user_agent: string | null;
  }>(
    `SELECT id, created_at, last_seen_at, expires_at, user_agent FROM sessions
      WHERE principal_id = $1 AND revoked_at IS NULL AND expires_at > now()
      ORDER BY last_seen_at DESC LIMIT 50`,
    [principalId],
  );
  return rows;
}

/** Remove sessions that ended more than a week ago. Run by the worker. */
export async function pruneSessions(pool: Pool): Promise<number> {
  const res = await pool.query(
    `DELETE FROM sessions
      WHERE expires_at < now() - interval '7 days'
         OR revoked_at < now() - interval '7 days'`,
  );
  return res.rowCount ?? 0;
}
