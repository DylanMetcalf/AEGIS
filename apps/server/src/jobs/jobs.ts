import type { JobDto, JobStatus } from '@aegis/shared';
import type { DbClient } from '../db/pool.js';
import { Errors } from '../http/errors.js';

export interface JobRow {
  id: string;
  tenant_id: string;
  actor_principal_id: string;
  kind: string;
  payload: Record<string, unknown>;
  idempotency_key: string | null;
  status: JobStatus;
  attempts: number;
  max_attempts: number;
  timeout_ms: number;
  run_after: Date;
  locked_by: string | null;
  locked_until: Date | null;
  last_error_code: string | null;
  result: Record<string, unknown> | null;
  correlation_id: string | null;
  created_at: Date;
  updated_at: Date;
  finished_at: Date | null;
}

export function toJobDto(r: JobRow): JobDto {
  return {
    id: r.id,
    kind: r.kind,
    status: r.status,
    attempts: r.attempts,
    maxAttempts: r.max_attempts,
    lastErrorCode: r.last_error_code,
    createdAt: r.created_at.toISOString(),
    finishedAt: r.finished_at?.toISOString() ?? null,
  };
}

/**
 * Enqueue a job in the caller's tenant transaction. The tenant and actor are
 * taken from the authenticated request, never from the payload. With an
 * idempotency key, a repeated request returns the original job instead of
 * creating a duplicate; reusing a key with a different payload is a conflict.
 */
export async function enqueueJob(
  client: DbClient,
  job: {
    tenantId: string;
    actorPrincipalId: string;
    kind: string;
    payload: Record<string, unknown>;
    idempotencyKey: string | null;
    maxAttempts: number;
    timeoutMs: number;
    correlationId: string | null;
  },
): Promise<{ job: JobRow; created: boolean }> {
  const { rows } = await client.query<JobRow>(
    `INSERT INTO jobs (tenant_id, actor_principal_id, kind, payload, idempotency_key,
                       max_attempts, timeout_ms, correlation_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     ON CONFLICT (tenant_id, kind, idempotency_key) DO NOTHING
     RETURNING *`,
    [
      job.tenantId,
      job.actorPrincipalId,
      job.kind,
      JSON.stringify(job.payload),
      job.idempotencyKey,
      job.maxAttempts,
      job.timeoutMs,
      job.correlationId,
    ],
  );
  if (rows[0]) return { job: rows[0], created: true };
  const existing = await client.query<JobRow>(
    'SELECT * FROM jobs WHERE tenant_id = $1 AND kind = $2 AND idempotency_key = $3',
    [job.tenantId, job.kind, job.idempotencyKey],
  );
  const prior = existing.rows[0];
  if (!prior) throw Errors.conflict();
  if (JSON.stringify(sortKeys(prior.payload)) !== JSON.stringify(sortKeys(job.payload))) {
    throw Errors.conflict('Idempotency key was already used for a different request');
  }
  return { job: prior, created: false };
}

function sortKeys(o: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(o).sort(([a], [b]) => a.localeCompare(b)));
}

export async function getJob(
  client: DbClient,
  tenantId: string,
  id: string,
): Promise<JobRow | null> {
  const { rows } = await client.query<JobRow>(
    'SELECT * FROM jobs WHERE tenant_id = $1 AND id = $2',
    [tenantId, id],
  );
  return rows[0] ?? null;
}
