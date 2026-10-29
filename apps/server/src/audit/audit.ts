import type { AuditActorType, AuditEventDto, AuditOutcome } from '@aegis/shared';
import { withTransaction, type DbClient, type Pool } from '../db/pool.js';
import { redact } from '../security/redact.js';

/**
 * Audit events record who did what to which target, when, and with what
 * outcome. Storage is append-only and hash-chained in the database (see
 * migration 0001). Metadata is redacted before it is written.
 */

export interface AuditEventInput {
  tenantId: string | null;
  actorPrincipalId: string | null;
  actorType: AuditActorType;
  action: string;
  targetType?: string | null;
  targetId?: string | null;
  outcome: AuditOutcome;
  reasonCode?: string | null;
  requestId?: string | null;
  correlationId?: string | null;
  metadata?: Record<string, unknown>;
}

const SAFE_ID = /^[A-Za-z0-9_.:@-]{1,128}$/;
const safeId = (v: string | null | undefined) => (v && SAFE_ID.test(v) ? v : null);

/**
 * Write an audit event using the caller's transaction, so that the event
 * commits or rolls back together with the change it describes. If the audit
 * write fails, the whole operation fails (fail closed).
 */
export async function recordAudit(client: DbClient, e: AuditEventInput): Promise<void> {
  await client.query(
    `INSERT INTO audit_events
       (tenant_id, actor_principal_id, actor_type, action, target_type, target_id,
        outcome, reason_code, request_id, correlation_id, metadata)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
    [
      e.tenantId,
      e.actorPrincipalId,
      e.actorType,
      e.action,
      e.targetType ?? null,
      safeId(e.targetId),
      e.outcome,
      e.reasonCode ?? null,
      safeId(e.requestId),
      safeId(e.correlationId),
      JSON.stringify(redact(e.metadata ?? {})),
    ],
  );
}

/**
 * Write an audit event in its own transaction. Used for denials and failures,
 * where the main transaction is being rolled back. Never throws: the caller
 * is already failing the request, and the failure to audit is logged.
 */
export async function recordAuditIndependently(
  pool: Pool,
  e: AuditEventInput,
  onError: (err: unknown) => void,
): Promise<void> {
  try {
    await withTransaction(
      pool,
      { tenantId: e.tenantId, principalId: e.actorPrincipalId },
      (client) => recordAudit(client, e),
    );
  } catch (err) {
    onError(err);
  }
}

interface AuditRow {
  id: string;
  chain_position: string;
  occurred_at: Date;
  tenant_id: string | null;
  actor_principal_id: string | null;
  actor_type: AuditActorType;
  action: string;
  target_type: string | null;
  target_id: string | null;
  outcome: AuditOutcome;
  reason_code: string | null;
  request_id: string | null;
  correlation_id: string | null;
  metadata: Record<string, unknown>;
}

export function toAuditDto(r: AuditRow): AuditEventDto {
  return {
    id: r.id,
    chainPosition: r.chain_position,
    occurredAt: r.occurred_at.toISOString(),
    tenantId: r.tenant_id,
    actorPrincipalId: r.actor_principal_id,
    actorType: r.actor_type,
    action: r.action,
    targetType: r.target_type,
    targetId: r.target_id,
    outcome: r.outcome,
    reasonCode: r.reason_code,
    requestId: r.request_id,
    correlationId: r.correlation_id,
    metadata: r.metadata,
  };
}

/**
 * List audit events visible in the current transaction context, newest
 * first. Row-level security restricts results to the active tenant (or to
 * platform events when platform scope is set); `scope` additionally makes
 * the intent explicit in the query.
 */
export async function listAuditEvents(
  client: DbClient,
  opts: {
    scope: { tenantId: string } | 'platform';
    limit: number;
    beforePosition?: string;
    action?: string;
    outcome?: AuditOutcome;
  },
): Promise<{ items: AuditEventDto[]; nextCursor: string | null }> {
  const where: string[] = [];
  const params: unknown[] = [];
  if (opts.scope === 'platform') {
    where.push('tenant_id IS NULL');
  } else {
    params.push(opts.scope.tenantId);
    where.push(`tenant_id = $${params.length}`);
  }
  if (opts.beforePosition) {
    params.push(opts.beforePosition);
    where.push(`chain_position < $${params.length}::bigint`);
  }
  if (opts.action) {
    params.push(opts.action);
    where.push(`action = $${params.length}`);
  }
  if (opts.outcome) {
    params.push(opts.outcome);
    where.push(`outcome = $${params.length}`);
  }
  params.push(opts.limit + 1);
  const { rows } = await client.query<AuditRow>(
    `SELECT id, chain_position, occurred_at, tenant_id, actor_principal_id, actor_type, action,
            target_type, target_id, outcome, reason_code, request_id, correlation_id, metadata
       FROM audit_events
      WHERE ${where.join(' AND ')}
      ORDER BY chain_position DESC
      LIMIT $${params.length}`,
    params,
  );
  const items = rows.slice(0, opts.limit).map(toAuditDto);
  const nextCursor = rows.length > opts.limit ? (items.at(-1)?.chainPosition ?? null) : null;
  return { items, nextCursor };
}

export interface ChainVerification {
  verified: boolean;
  eventsChecked: number;
  firstInvalidPosition: string | null;
  reason: string | null;
  headPosition: string | null;
  headHash: string | null;
  verifiedAt: string;
}

export async function verifyAuditChain(pool: Pool): Promise<ChainVerification> {
  const { rows } = await pool.query<{
    verified: boolean;
    events_checked: string;
    first_invalid_position: string | null;
    reason: string | null;
    head_position: string | null;
    head_hash: string | null;
  }>('SELECT * FROM audit_verify_chain()');
  const r = rows[0]!;
  return {
    verified: r.verified,
    eventsChecked: Number(r.events_checked),
    firstInvalidPosition: r.first_invalid_position,
    reason: r.reason,
    headPosition: r.head_position,
    headHash: r.head_hash,
    verifiedAt: new Date().toISOString(),
  };
}
